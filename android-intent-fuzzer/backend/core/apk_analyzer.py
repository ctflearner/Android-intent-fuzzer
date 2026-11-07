"""Static APK analysis engine for IntentHunter.

Decompiles APK via jadx, parses manifest, extracts attack surface data.
Memory-efficient: streams file scanning with generators, lazy XML parsing.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Generator

from backend.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns for hardcoded secret detection
# ---------------------------------------------------------------------------
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key", re.compile(r"""(?:aws_secret|secret_key|SECRET_KEY)\s*[=:]\s*["']([A-Za-z0-9/+=]{40})["']""")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Firebase URL", re.compile(r"https://[a-z0-9-]+\.firebaseio\.com")),
    ("Firebase API Key", re.compile(r"(?:firebase|FIREBASE).*?[=:]\s*[\"']([A-Za-z0-9_\-]{20,})[\"']")),
    ("Generic API Key", re.compile(r"""(?:api[_-]?key|apikey|API_KEY)\s*[=:]\s*["']([A-Za-z0-9_\-]{16,})["']""")),
    ("Generic Secret", re.compile(r"""(?:secret|SECRET|password|PASSWORD|passwd)\s*[=:]\s*["']([^"']{8,})["']""")),
    ("JWT Token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("OAuth Token", re.compile(r"""(?:oauth|bearer|token)\s*[=:]\s*["']([A-Za-z0-9_\-\.]{20,})["']""", re.IGNORECASE)),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9]{10,}-[0-9A-Za-z]{10,}")),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}")),
    ("Twilio Key", re.compile(r"SK[0-9a-fA-F]{32}")),
    ("Hardcoded URL Creds", re.compile(r"https?://[^/\s:]+:[^/\s@]+@[^\s]+")),
]

# Paths to skip during secret scanning (case-insensitive stem match)
SKIP_DIRS = {"android", "androidx", "google", "kotlin", "kotlinx", "okhttp3",
             "retrofit2", "com/google", "org/apache", "org/bouncycastle"}

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class IntentFilterInfo:
    actions: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    data_schemes: list[str] = field(default_factory=list)
    data_hosts: list[str] = field(default_factory=list)
    data_paths: list[str] = field(default_factory=list)
    data_mime_types: list[str] = field(default_factory=list)


@dataclass
class ComponentInfo:
    component_type: str  # activity, service, receiver, provider
    name: str
    exported: bool = False
    permission: str | None = None
    intent_filters: list[IntentFilterInfo] = field(default_factory=list)
    deep_links: list[str] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class SecretFinding:
    pattern_name: str
    file_path: str
    line_number: int
    matched_text: str
    context: str = ""  # surrounding line


@dataclass
class NetworkSecurityConfig:
    cleartextTrafficPermitted: bool = False
    trust_user_certs: bool = False
    pin_sets: list[dict[str, Any]] = field(default_factory=list)
    domain_configs: list[dict[str, Any]] = field(default_factory=list)
    raw_xml: str = ""


@dataclass
class APKAnalysis:
    apk_path: str
    decompiled_path: str = ""
    package_name: str = ""
    app_version: str = ""
    min_sdk: int = 0
    target_sdk: int = 0
    permissions: list[str] = field(default_factory=list)
    debuggable: bool = False
    allow_backup: bool = True
    shared_uid: str | None = None
    components: list[ComponentInfo] = field(default_factory=list)
    deep_link_schemes: list[str] = field(default_factory=list)
    hardcoded_secrets: list[SecretFinding] = field(default_factory=list)
    native_libs: list[str] = field(default_factory=list)
    secret_codes: list[str] = field(default_factory=list)
    network_security: NetworkSecurityConfig | None = None
    attack_surface_score: float = 0.0
    manifest_raw: str = ""

    @property
    def exported_components(self) -> list[ComponentInfo]:
        return [c for c in self.components if c.exported]


# ---------------------------------------------------------------------------
# Namespace helpers for AndroidManifest
# ---------------------------------------------------------------------------
ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _attr(elem: ET.Element, name: str, ns: str = ANDROID_NS) -> str:
    return elem.get(f"{{{ns}}}{name}", "")


def _attr_bool(elem: ET.Element, name: str, default: bool = False) -> bool:
    val = _attr(elem, name).lower()
    if val == "true":
        return True
    if val == "false":
        return False
    return default


# ---------------------------------------------------------------------------
# APKAnalyzer
# ---------------------------------------------------------------------------

class APKAnalyzer:
    """Static analysis engine. All heavy I/O is async."""

    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self._apk_name = Path(apk_path).stem
        self.output_dir = settings.decompiled_dir / self._apk_name

    async def analyze(self) -> APKAnalysis:
        """Run full static analysis pipeline. Returns populated APKAnalysis."""
        analysis = APKAnalysis(apk_path=self.apk_path)

        # Step 1: Decompile
        await self._decompile()
        analysis.decompiled_path = str(self.output_dir)

        # Step 2: Parse manifest
        manifest_path = self._find_manifest()
        if manifest_path:
            manifest_xml = manifest_path.read_text(encoding="utf-8", errors="replace")
            analysis.manifest_raw = manifest_xml
            self._parse_manifest(manifest_xml, analysis)

        # Step 3: Extract native libs from APK directly (avoids decompressing everything)
        analysis.native_libs = self._extract_native_libs()

        # Step 4: Parse network_security_config.xml
        analysis.network_security = self._parse_network_security()

        # Step 5: Scan for hardcoded secrets (generator-based, memory efficient)
        analysis.hardcoded_secrets = list(self._scan_secrets())

        # Step 6: Collect deep link schemes across all components
        schemes: set[str] = set()
        for comp in analysis.components:
            for dl in comp.deep_links:
                scheme = dl.split("://")[0] if "://" in dl else dl
                schemes.add(scheme)
            for filt in comp.intent_filters:
                schemes.update(filt.data_schemes)
        analysis.deep_link_schemes = sorted(schemes)

        # Step 7: Calculate attack surface score
        analysis.attack_surface_score = self._calculate_attack_surface(analysis)

        logger.info(
            "Analysis complete: pkg=%s components=%d exported=%d secrets=%d score=%.1f",
            analysis.package_name,
            len(analysis.components),
            len(analysis.exported_components),
            len(analysis.hardcoded_secrets),
            analysis.attack_surface_score,
        )

        return analysis

    # ------------------------------------------------------------------
    # Decompilation
    # ------------------------------------------------------------------

    async def _decompile(self) -> None:
        """Decompile APK using jadx (async subprocess)."""
        if self.output_dir.exists() and any(self.output_dir.iterdir()):
            logger.info("Decompiled output already exists at %s, skipping", self.output_dir)
            return

        self.output_dir.mkdir(parents=True, exist_ok=True)
        jadx = settings.jadx_path
        cmd = [
            jadx,
            "--no-imports",
            "--deobf",
            "--threads-count", str(min(os.cpu_count() or 2, 4)),
            "-d", str(self.output_dir),
            self.apk_path,
        ]
        logger.info("Decompiling APK: %s", " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)

        if proc.returncode != 0:
            err_text = stderr.decode("utf-8", errors="replace")[:2000]
            logger.error("jadx failed (rc=%d): %s", proc.returncode, err_text)
            raise RuntimeError(f"jadx decompilation failed: {err_text}")

        logger.info("Decompilation complete: %s", self.output_dir)

    # ------------------------------------------------------------------
    # Manifest parsing
    # ------------------------------------------------------------------

    def _find_manifest(self) -> Path | None:
        """Locate AndroidManifest.xml in decompiled output."""
        candidates = [
            self.output_dir / "resources" / "AndroidManifest.xml",
            self.output_dir / "AndroidManifest.xml",
        ]
        for c in candidates:
            if c.is_file():
                return c
        # Fallback: search recursively (limit depth)
        for f in self.output_dir.rglob("AndroidManifest.xml"):
            return f
        return None

    def _parse_manifest(self, xml_text: str, analysis: APKAnalysis) -> None:
        """Parse AndroidManifest.xml and populate analysis fields."""
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as e:
            logger.error("Failed to parse AndroidManifest.xml: %s", e)
            return

        # Package info
        analysis.package_name = root.get("package", "")

        # SDK versions
        uses_sdk = root.find("uses-sdk")
        if uses_sdk is not None:
            min_sdk = _attr(uses_sdk, "minSdkVersion")
            target_sdk = _attr(uses_sdk, "targetSdkVersion")
            analysis.min_sdk = int(min_sdk) if min_sdk.isdigit() else 0
            analysis.target_sdk = int(target_sdk) if target_sdk.isdigit() else 0

        # Permissions
        analysis.permissions = [
            _attr(elem, "name")
            for elem in root.iter("uses-permission")
            if _attr(elem, "name")
        ]

        # Application-level attributes
        app_elem = root.find("application")
        if app_elem is not None:
            analysis.debuggable = _attr_bool(app_elem, "debuggable", False)
            analysis.allow_backup = _attr_bool(app_elem, "allowBackup", True)

        # Shared UID
        analysis.shared_uid = _attr(root, "sharedUserId") or None

        # Version
        analysis.app_version = _attr(root, "versionName") or _attr(root, "versionCode")

        # Components
        component_tags = {
            "activity": "activity",
            "activity-alias": "activity",
            "service": "service",
            "receiver": "receiver",
            "provider": "provider",
        }

        if app_elem is not None:
            for tag, comp_type in component_tags.items():
                for elem in app_elem.iter(tag):
                    comp = self._parse_component(elem, comp_type, analysis.package_name)
                    if comp:
                        analysis.components.append(comp)

            # Secret codes from receivers with android_secret_code scheme
            for comp in analysis.components:
                for filt in comp.intent_filters:
                    if "android_secret_code" in filt.data_schemes:
                        for host in filt.data_hosts:
                            if host:
                                analysis.secret_codes.append(host)

    def _parse_component(
        self, elem: ET.Element, comp_type: str, package_name: str
    ) -> ComponentInfo | None:
        """Parse a single component element from the manifest."""
        name = _attr(elem, "name")
        if not name:
            return None

        # Resolve relative class names
        if name.startswith("."):
            name = package_name + name
        elif "." not in name:
            name = f"{package_name}.{name}"

        # Determine exported status
        exported_attr = _attr(elem, "exported")
        has_intent_filters = elem.find("intent-filter") is not None

        if exported_attr.lower() == "true":
            exported = True
        elif exported_attr.lower() == "false":
            exported = False
        else:
            # Default: exported=true if has intent-filters (pre-API 31 behavior)
            exported = has_intent_filters

        permission = _attr(elem, "permission") or None

        # Intent filters
        intent_filters: list[IntentFilterInfo] = []
        deep_links: list[str] = []

        for if_elem in elem.iter("intent-filter"):
            filt = IntentFilterInfo()

            for action_elem in if_elem.iter("action"):
                action_name = _attr(action_elem, "name")
                if action_name:
                    filt.actions.append(action_name)

            for cat_elem in if_elem.iter("category"):
                cat_name = _attr(cat_elem, "name")
                if cat_name:
                    filt.categories.append(cat_name)

            for data_elem in if_elem.iter("data"):
                scheme = _attr(data_elem, "scheme")
                host = _attr(data_elem, "host")
                path = _attr(data_elem, "path") or _attr(data_elem, "pathPrefix") or _attr(data_elem, "pathPattern")
                mime = _attr(data_elem, "mimeType")

                if scheme:
                    filt.data_schemes.append(scheme)
                if host:
                    filt.data_hosts.append(host)
                if path:
                    filt.data_paths.append(path)
                if mime:
                    filt.data_mime_types.append(mime)

                # Build deep link URI
                if scheme and host:
                    dl = f"{scheme}://{host}"
                    if path:
                        dl += path
                    deep_links.append(dl)

            intent_filters.append(filt)

        # Metadata
        metadata: dict[str, str] = {}
        for meta_elem in elem.iter("meta-data"):
            meta_name = _attr(meta_elem, "name")
            meta_value = _attr(meta_elem, "value") or _attr(meta_elem, "resource")
            if meta_name:
                metadata[meta_name] = meta_value

        return ComponentInfo(
            component_type=comp_type,
            name=name,
            exported=exported,
            permission=permission,
            intent_filters=intent_filters,
            deep_links=deep_links,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Native library extraction (directly from APK zip)
    # ------------------------------------------------------------------

    def _extract_native_libs(self) -> list[str]:
        """List .so files inside the APK without full extraction."""
        libs: list[str] = []
        try:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                for entry in zf.namelist():
                    if entry.endswith(".so") and entry.startswith("lib/"):
                        libs.append(entry)
        except (zipfile.BadZipFile, OSError) as e:
            logger.warning("Failed to read APK as zip: %s", e)
        return libs

    # ------------------------------------------------------------------
    # Network security config
    # ------------------------------------------------------------------

    def _parse_network_security(self) -> NetworkSecurityConfig | None:
        """Parse network_security_config.xml if present."""
        candidates = [
            self.output_dir / "resources" / "res" / "xml" / "network_security_config.xml",
            self.output_dir / "res" / "xml" / "network_security_config.xml",
        ]
        config_path = None
        for c in candidates:
            if c.is_file():
                config_path = c
                break

        if config_path is None:
            # Fallback search
            for f in self.output_dir.rglob("network_security_config.xml"):
                config_path = f
                break

        if config_path is None:
            return None

        try:
            raw_xml = config_path.read_text(encoding="utf-8", errors="replace")
            root = ET.fromstring(raw_xml)
        except (ET.ParseError, OSError) as e:
            logger.warning("Failed to parse network_security_config.xml: %s", e)
            return None

        nsc = NetworkSecurityConfig(raw_xml=raw_xml)

        # Base config
        base_config = root.find("base-config")
        if base_config is not None:
            nsc.cleartextTrafficPermitted = base_config.get(
                "cleartextTrafficPermitted", "false"
            ).lower() == "true"

            trust_anchors = base_config.find("trust-anchors")
            if trust_anchors is not None:
                for cert in trust_anchors.iter("certificates"):
                    if cert.get("src", "") == "user":
                        nsc.trust_user_certs = True

        # Domain configs
        for dc in root.iter("domain-config"):
            domains = [d.text or "" for d in dc.iter("domain")]
            cleartext = dc.get("cleartextTrafficPermitted", "")
            trust_user = False
            ta = dc.find("trust-anchors")
            if ta is not None:
                for cert in ta.iter("certificates"):
                    if cert.get("src", "") == "user":
                        trust_user = True

            pins = []
            pin_set = dc.find("pin-set")
            if pin_set is not None:
                expiry = pin_set.get("expiration", "")
                for pin in pin_set.iter("pin"):
                    pins.append({
                        "digest": pin.get("digest", ""),
                        "value": (pin.text or "").strip(),
                        "expiration": expiry,
                    })
                nsc.pin_sets.extend(pins)

            nsc.domain_configs.append({
                "domains": domains,
                "cleartextTrafficPermitted": cleartext.lower() == "true" if cleartext else None,
                "trust_user_certs": trust_user,
                "pins": pins,
            })

        return nsc

    # ------------------------------------------------------------------
    # Secret scanning (generator-based for memory efficiency)
    # ------------------------------------------------------------------

    def _scan_secrets(self) -> Generator[SecretFinding, None, None]:
        """Scan decompiled Java/Kotlin source for hardcoded secrets.

        Uses a generator to avoid loading all findings into memory at once.
        Skips known library directories to reduce false positives.
        """
        sources_dir = self.output_dir / "sources"
        if not sources_dir.is_dir():
            # jadx sometimes uses different output structure
            sources_dir = self.output_dir
            if not sources_dir.is_dir():
                return

        for root_dir, dirs, files in os.walk(sources_dir):
            # Prune library directories
            rel = os.path.relpath(root_dir, sources_dir).replace(os.sep, "/")
            skip = False
            for skip_dir in SKIP_DIRS:
                if rel.startswith(skip_dir) or f"/{skip_dir}" in rel:
                    skip = True
                    break
            if skip:
                dirs.clear()
                continue

            for fname in files:
                if not fname.endswith((".java", ".kt", ".xml", ".json", ".properties")):
                    continue
                fpath = os.path.join(root_dir, fname)
                yield from self._scan_file_secrets(fpath)

    def _scan_file_secrets(self, file_path: str) -> Generator[SecretFinding, None, None]:
        """Scan a single file for secret patterns. Reads line-by-line."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                for line_num, line in enumerate(f, 1):
                    for pattern_name, pattern in SECRET_PATTERNS:
                        match = pattern.search(line)
                        if match:
                            matched_text = match.group(0)
                            # Skip obvious false positives
                            if self._is_false_positive(matched_text, line):
                                continue
                            yield SecretFinding(
                                pattern_name=pattern_name,
                                file_path=os.path.relpath(file_path, str(self.output_dir)),
                                line_number=line_num,
                                matched_text=matched_text[:200],
                                context=line.strip()[:300],
                            )
        except OSError:
            pass

    @staticmethod
    def _is_false_positive(matched: str, line: str) -> bool:
        """Basic false-positive filtering for secret matches."""
        lower_line = line.lower()
        # Skip example/placeholder values
        placeholders = {"your_api_key", "xxx", "changeme", "replace_me", "todo",
                        "example", "placeholder", "insert_here", "your_key_here",
                        "0000000000000000", "aaaaaaaaaa"}
        matched_lower = matched.lower()
        for ph in placeholders:
            if ph in matched_lower:
                return True
        # Skip test/mock files
        if "test" in lower_line or "mock" in lower_line or "sample" in lower_line:
            return True
        # Skip comments
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            return True
        return False

    # ------------------------------------------------------------------
    # Attack surface scoring
    # ------------------------------------------------------------------

    @staticmethod
    def _calculate_attack_surface(analysis: APKAnalysis) -> float:
        """Weighted attack surface score (0-100).

        Weights:
          - Exported components: 3 pts each (max 30)
          - Deep link schemes: 4 pts each (max 20)
          - Debuggable: +15
          - Allow backup: +5
          - Hardcoded secrets: 2 pts each (max 15)
          - Dangerous permissions: 1 pt each (max 10)
          - Missing network security: +5
        """
        score = 0.0

        # Exported components
        score += min(len(analysis.exported_components) * 3.0, 30.0)

        # Deep links
        score += min(len(analysis.deep_link_schemes) * 4.0, 20.0)

        # Flags
        if analysis.debuggable:
            score += 15.0
        if analysis.allow_backup:
            score += 5.0

        # Secrets
        score += min(len(analysis.hardcoded_secrets) * 2.0, 15.0)

        # Dangerous permissions
        dangerous = {
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_PHONE_STATE",
        }
        dangerous_count = sum(1 for p in analysis.permissions if p in dangerous)
        score += min(dangerous_count * 1.0, 10.0)

        # Weak network security
        if analysis.network_security is None:
            score += 2.0
        elif analysis.network_security.cleartextTrafficPermitted:
            score += 5.0

        return min(score, 100.0)
