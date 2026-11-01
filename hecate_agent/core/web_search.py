"""Web search integration for threat research."""

import contextlib
import hashlib
import json
import logging
import os
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from hecate_agent.core.sqlite_utils import connect_sqlite

logger = logging.getLogger(__name__)


@dataclass
class SearchResult:
    """Single search result."""

    title: str
    url: str
    content: str  # Snippet or full content
    score: float  # Relevance score (0-1)


@dataclass
class SearchResponse:
    """Web search response."""

    query: str
    results: List[SearchResult]
    answer: Optional[str] = None  # AI-generated answer summary
    response_time_ms: int = 0
    search_depth: str = "basic"
    images: List[Dict[str, str]] = field(default_factory=list)


class WebSearchCache:
    """Persistent SQLite cache for web search responses to eliminate duplicate Tavily API calls."""

    def __init__(
        self,
        db_path: Optional[Path | str] = None,
        ttl_days: int = 7,
        enabled: bool = True,
    ) -> None:
        self.enabled = enabled
        self.ttl_seconds = ttl_days * 86400

        if db_path is None:
            env_path = os.getenv("HECATE_SEARCH_CACHE_PATH")
            if env_path:
                self.db_path = Path(env_path)
            else:
                workspace = os.getenv("HECATE_WORKSPACE")
                if workspace:
                    self.db_path = Path(workspace) / "hecate_search_cache.sqlite"
                else:
                    self.db_path = Path.cwd() / "hecate_search_cache.sqlite"
        else:
            self.db_path = Path(db_path)

        if self.enabled:
            self._init_db()

    @contextlib.contextmanager
    def _connect(self, timeout: float = 5.0) -> Iterator[sqlite3.Connection]:
        conn = connect_sqlite(self.db_path, timeout=timeout, wal=True, busy_timeout_ms=5000)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            with self._connect(timeout=10.0) as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS search_cache (
                        cache_key TEXT PRIMARY KEY,
                        query TEXT NOT NULL,
                        search_depth TEXT NOT NULL,
                        response_json TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        expires_at REAL NOT NULL
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_search_cache_expires ON search_cache (expires_at)")
        except Exception as exc:
            logger.warning("Failed to initialize search cache at %s: %s", self.db_path, exc)

    @staticmethod
    def compute_cache_key(
        query: str,
        search_depth: str,
        max_results: int,
        include_domains: Optional[List[str]],
        exclude_domains: Optional[List[str]],
        include_answer: bool,
        include_raw_content: bool,
        min_score: float,
    ) -> str:
        key_data = [
            query.strip().lower(),
            search_depth,
            max_results,
            sorted(include_domains or []),
            sorted(exclude_domains or []),
            include_answer,
            include_raw_content,
            round(min_score, 3),
        ]
        return hashlib.sha256(json.dumps(key_data).encode("utf-8")).hexdigest()

    def get(self, cache_key: str) -> Optional[SearchResponse]:
        if not self.enabled:
            return None
        try:
            now = time.time()
            with self._connect(timeout=5.0) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT response_json, expires_at FROM search_cache WHERE cache_key = ?",
                    (cache_key,),
                )
                row = cursor.fetchone()
                if row:
                    response_json, expires_at = row
                    if expires_at > now:
                        data = json.loads(response_json)
                        results = [
                            SearchResult(
                                title=r["title"],
                                url=r["url"],
                                content=r["content"],
                                score=r.get("score", 0.0),
                            )
                            for r in data.get("results", [])
                        ]
                        return SearchResponse(
                            query=data.get("query", ""),
                            results=results,
                            answer=data.get("answer"),
                            response_time_ms=0,
                            search_depth=data.get("search_depth", "basic"),
                            images=data.get("images", []),
                        )
                    else:
                        conn.execute("DELETE FROM search_cache WHERE cache_key = ?", (cache_key,))
        except Exception as exc:
            logger.debug("Search cache read error: %s", exc)
        return None

    def set(self, cache_key: str, query: str, search_depth: str, response: SearchResponse) -> None:
        if not self.enabled:
            return
        try:
            now = time.time()
            expires_at = now + self.ttl_seconds
            data = {
                "query": response.query,
                "answer": response.answer,
                "search_depth": response.search_depth,
                "images": response.images,
                "results": [
                    {
                        "title": r.title,
                        "url": r.url,
                        "content": r.content,
                        "score": r.score,
                    }
                    for r in response.results
                ],
            }
            with self._connect(timeout=5.0) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO search_cache 
                    (cache_key, query, search_depth, response_json, created_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (cache_key, query, search_depth, json.dumps(data), now, expires_at),
                )
        except Exception as exc:
            logger.debug("Search cache write error: %s", exc)


class TavilySearchClient:
    """Tavily Search API client for threat research.

    Tavily is designed for AI/LLM integration and provides:
    - Basic and advanced search depth
    - AI-generated answer summaries
    - Domain filtering
    - Structured results for LLM consumption

    Features:
    - Security-focused domain filtering
    - Configurable search depth (basic=fast, advanced=thorough)
    - Graceful error handling with fallbacks
    - Cost tracking

    Environment:
        TAVILY_API_KEY: API key from https://tavily.com
    """

    SECURITY_DOMAINS = [
        "attack.mitre.org",
        "github.com",
        "elastic.co",
        "microsoft.com",
        "crowdstrike.com",
        "mandiant.com",
        "redcanary.com",
        "thehackernews.com",
        "bleepingcomputer.com",
        "unit42.paloaltonetworks.com",
        "blog.talosintelligence.com",
        "securelist.com",
        "thedfirreport.com",
        "atomicredteam.io",
        "lolbas-project.github.io",
        "gtfobins.github.io",
    ]

    # Applied to search_system_internals/search_adversary_tradecraft (the
    # skills that don't use include_domains -- see the comments there for why
    # that allowlist was dropped). Two narrow, low-maintenance categories that
    # are never a legitimate *primary* research citation regardless of topic,
    # observed as real problems in production research docs:
    # - Social/reposting platforms: Tavily returns the same underlying
    #   article re-shared across several of these as if they were
    #   independent corroborating sources (observed: one Hacker News piece
    #   cited 5 times over Facebook/LinkedIn/X/Threads/Reddit in one doc).
    # - URL shorteners/trackers: not research content at all (observed:
    #   grabify.org -- an IP-logging link tool -- cited as a source).
    EXCLUDE_DOMAINS = [
        "facebook.com",
        "x.com",
        "twitter.com",
        "linkedin.com",
        "threads.com",
        "reddit.com",
        "instagram.com",
        "tiktok.com",
        "grabify.org",
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "ow.ly",
    ]

    def __init__(
        self,
        api_key: Optional[str] = None,
        cache: Optional[WebSearchCache] = None,
        cache_enabled: Optional[bool] = None,
        cache_path: Optional[Path | str] = None,
        cache_ttl_days: Optional[int] = None,
    ) -> None:
        """Initialize client with API key and local response cache.

        Args:
            api_key: Tavily API key (defaults to TAVILY_API_KEY env var)
            cache: Pre-configured WebSearchCache instance
            cache_enabled: Whether to enable SQLite search caching (defaults to env or True)
            cache_path: Custom SQLite database path
            cache_ttl_days: Cache retention TTL in days (defaults to 7)

        Raises:
            ValueError: If no API key is provided or found
        """
        self.api_key = api_key or os.getenv("TAVILY_API_KEY")
        if not self.api_key:
            raise ValueError("TAVILY_API_KEY not set. Get your API key from https://tavily.com")
        self._client: Optional[Any] = None

        if cache is not None:
            self.cache = cache
        else:
            if cache_enabled is None:
                cache_enabled = os.getenv("HECATE_SEARCH_CACHE_ENABLED", "true").lower() in (
                    "true",
                    "1",
                    "yes",
                )
            if cache_ttl_days is None:
                try:
                    cache_ttl_days = int(os.getenv("HECATE_SEARCH_CACHE_TTL_DAYS", "7"))
                except ValueError:
                    cache_ttl_days = 7
            self.cache = WebSearchCache(
                db_path=cache_path,
                ttl_days=cache_ttl_days,
                enabled=cache_enabled,
            )

    def _get_client(self) -> Any:
        """Get or create Tavily client instance."""
        if self._client is None:
            try:
                from tavily import TavilyClient

                self._client = TavilyClient(api_key=self.api_key)
            except ImportError:
                raise ImportError("tavily-python package not installed. Run: pip install tavily-python")
        return self._client

    # Empirically chosen (see search_system_internals/search_adversary_tradecraft):
    # for a narrow, specific topic (e.g. a malware family name), on-topic results
    # scored 0.45-0.82 while off-topic filler scored 0.09-0.26 -- 0.3 sits
    # cleanly in the observed gap between the two clusters.
    MIN_RELEVANCE_SCORE = 0.3

    def search(
        self,
        query: str,
        search_depth: str = "basic",
        max_results: int = 10,
        include_domains: Optional[List[str]] = None,
        exclude_domains: Optional[List[str]] = None,
        include_answer: bool = True,
        include_raw_content: bool = False,
        min_score: float = MIN_RELEVANCE_SCORE,
    ) -> SearchResponse:
        """Execute search query.

        Args:
            query: Search query string
            search_depth: "basic" (fast, ~5 results) or "advanced" (thorough, ~10 results)
            max_results: Maximum number of results (1-20)
            include_domains: Limit search to these domains
            exclude_domains: Exclude these domains from search
            include_answer: Include AI-generated answer summary
            include_raw_content: Include full page content (increases response size)
            min_score: Drop results below this Tavily relevance score. Acts as a
                backstop against low-relevance filler -- most relevant when
                include_domains is empty/broad enough that Tavily has to return
                *something* even for a niche topic with little real coverage.

        Returns:
            SearchResponse with results

        Raises:
            Exception: If search fails
        """
        cache_key = WebSearchCache.compute_cache_key(
            query=query,
            search_depth=search_depth,
            max_results=max_results,
            include_domains=include_domains,
            exclude_domains=exclude_domains,
            include_answer=include_answer,
            include_raw_content=include_raw_content,
            min_score=min_score,
        )

        cached_response = self.cache.get(cache_key)
        if cached_response is not None:
            logger.info("Search cache HIT for query: %s", query)
            return cached_response

        client = self._get_client()

        start_time = time.time()

        # Build search parameters
        search_params: Dict[str, Any] = {
            "query": query,
            "search_depth": search_depth,
            "max_results": max_results,
            "include_answer": include_answer,
            "include_raw_content": include_raw_content,
        }

        if include_domains:
            search_params["include_domains"] = include_domains

        if exclude_domains:
            search_params["exclude_domains"] = exclude_domains

        # Execute search
        response = client.search(**search_params)

        response_time_ms = int((time.time() - start_time) * 1000)

        # Parse results, dropping anything below the relevance floor
        results = []
        for result in response.get("results", []):
            score = result.get("score", 0.0)
            if score < min_score:
                continue
            results.append(
                SearchResult(
                    title=result.get("title", ""),
                    url=result.get("url", ""),
                    content=result.get("content", ""),
                    score=score,
                )
            )

        search_resp = SearchResponse(
            query=query,
            results=results,
            answer=response.get("answer"),
            response_time_ms=response_time_ms,
            search_depth=search_depth,
            images=response.get("images", []),
        )
        self.cache.set(cache_key, query, search_depth, search_resp)
        return search_resp

    def search_threat_intel(
        self,
        topic: str,
        technique: Optional[str] = None,
        search_depth: str = "advanced",
    ) -> SearchResponse:
        """Search with security-focused parameters.

        Optimized for threat hunting research with:
        - Security-focused domain filtering
        - Advanced search depth by default
        - AI-generated answer summary

        Args:
            topic: Research topic (e.g., "LSASS memory dumping")
            technique: Optional MITRE ATT&CK technique (e.g., "T1003.001")
            search_depth: Search depth ("basic" or "advanced")

        Returns:
            SearchResponse with security-focused results
        """
        # Build security-focused query
        query = f"{topic} threat hunting detection"
        if technique:
            query += f" MITRE ATT&CK {technique}"

        return self.search(
            query=query,
            search_depth=search_depth,
            include_domains=self.SECURITY_DOMAINS,
            include_answer=True,
        )

    def search_system_internals(
        self,
        topic: str,
        search_depth: str = "advanced",
    ) -> SearchResponse:
        """Search for system/technology internals.

        Focused on understanding how systems work normally,
        useful for the "System Research" skill.

        Args:
            topic: Technology/system topic (e.g., "LSASS", "Windows Authentication")
            search_depth: Search depth ("basic" or "advanced")

        Returns:
            SearchResponse with technical documentation
        """
        query = f"{topic} how it works internals documentation"

        # No include_domains: this skill's topic is very often a malware/threat-
        # actor name rather than a legitimate protocol/OS feature, and a fixed
        # protocol-documentation allowlist (microsoft.com/kernel.org/man7.org/...)
        # has essentially no real coverage of a given malware family. Measured
        # against a real topic: domain-restricted top result scored 0.38 (a
        # Microsoft Q&A forum post) with the rest of the top 5 being unrelated
        # kernel.org driver docs (score 0.22-0.26); unrestricted, the top result
        # (score 0.82) was the actual source article, and all 10 results were
        # genuinely on-topic. min_score on search() is the backstop against
        # low-relevance filler now that there's no domain allowlist to lean on.
        # EXCLUDE_DOMAINS drops social-media reposts and URL-tracker tools --
        # see its own comment for why.
        return self.search(
            query=query,
            search_depth=search_depth,
            include_answer=True,
            exclude_domains=self.EXCLUDE_DOMAINS,
        )

    def search_adversary_tradecraft(
        self,
        topic: str,
        technique: Optional[str] = None,
        search_depth: str = "advanced",
    ) -> SearchResponse:
        """Search for adversary tradecraft and attack techniques.

        Focused on how adversaries abuse systems,
        useful for the "Adversary Tradecraft" skill.

        Args:
            topic: Attack topic (e.g., "credential dumping", "lateral movement")
            technique: Optional MITRE ATT&CK technique
            search_depth: Search depth ("basic" or "advanced")

        Returns:
            SearchResponse with adversary technique information
        """
        query = f"{topic} adversary technique attack method"
        if technique:
            query += f" {technique}"

        # No include_domains: this list of threat-intel vendor domains still
        # missed real, relevant coverage (SC Media, Cybereason, Hacker News
        # weren't in it), and for a narrow/specific topic Tavily runs out of
        # genuinely relevant hits within it -- measured case: correct top 2
        # results (score 0.64-0.68) followed by four duplicate, unrelated MITRE
        # technique pages (score 0.09-0.17) padding out the rest. Unrestricted,
        # relevance stayed high (0.45-0.79) throughout all 10 results. min_score
        # on search() is the backstop against low-relevance filler now that
        # there's no domain allowlist to lean on.
        # EXCLUDE_DOMAINS drops social-media reposts and URL-tracker tools --
        # see its own comment for why.
        return self.search(
            query=query,
            search_depth=search_depth,
            include_answer=True,
            exclude_domains=self.EXCLUDE_DOMAINS,
        )

    def search_detection_methods(
        self,
        topic: str,
        technique: Optional[str] = None,
        search_depth: str = "advanced",
    ) -> SearchResponse:
        """Search for detection methods and analytics.

        Focused on how to detect specific behaviors,
        useful for detection engineering.

        Args:
            topic: Detection topic (e.g., "LSASS access detection")
            technique: Optional MITRE ATT&CK technique
            search_depth: Search depth ("basic" or "advanced")

        Returns:
            SearchResponse with detection method information
        """
        query = f"{topic} detection rule query sigma"
        if technique:
            query += f" {technique}"

        # Focus on detection and SIEM sources
        detection_domains = [
            "github.com",
            "elastic.co",
            "splunk.com",
            "microsoft.com",
            "redcanary.com",
            "sigma-hq.github.io",
            "detection.fyi",
        ]

        return self.search(
            query=query,
            search_depth=search_depth,
            include_domains=detection_domains,
            include_answer=True,
        )


def create_search_client(
    api_key: Optional[str] = None,
    cache: Optional[WebSearchCache] = None,
    cache_enabled: Optional[bool] = None,
    cache_path: Optional[Path | str] = None,
    cache_ttl_days: Optional[int] = None,
) -> Optional[TavilySearchClient]:
    """Create a Tavily search client if API key is available.

    Args:
        api_key: Optional API key (defaults to TAVILY_API_KEY env var)
        cache: Optional pre-configured WebSearchCache
        cache_enabled: Whether to enable SQLite search caching
        cache_path: Custom SQLite database path
        cache_ttl_days: Cache retention TTL in days

    Returns:
        TavilySearchClient if API key is available, None otherwise
    """
    key = api_key or os.getenv("TAVILY_API_KEY")
    if not key:
        return None
    return TavilySearchClient(
        api_key=key,
        cache=cache,
        cache_enabled=cache_enabled,
        cache_path=cache_path,
        cache_ttl_days=cache_ttl_days,
    )
