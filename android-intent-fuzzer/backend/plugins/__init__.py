"""IntentHunter plugin registry — all 14 plugins."""

from backend.plugins.base import BasePlugin, PluginCategory, PluginFinding, IntentSpec, PoC, ValidationVerdict

from backend.plugins.intent_fuzzer import IntentFuzzerPlugin
from backend.plugins.content_provider import ContentProviderPlugin
from backend.plugins.deeplink_fuzzer import DeepLinkPlugin
from backend.plugins.broadcast_analyzer import BroadcastPlugin
from backend.plugins.service_binder import ServiceBinderPlugin
from backend.plugins.webview_exploiter import WebViewPlugin
from backend.plugins.task_hijacker import TaskHijackPlugin
from backend.plugins.fragment_injector import FragmentInjectorPlugin
from backend.plugins.pending_intent import PendingIntentPlugin
from backend.plugins.file_provider import FileProviderPlugin
from backend.plugins.backup_extractor import BackupExtractorPlugin
from backend.plugins.storage_analyzer import StorageAnalyzerPlugin
from backend.plugins.attack_chain import AttackChainPlugin
from backend.plugins.exploit_validator import ExploitValidatorPlugin

ALL_PLUGINS: dict[str, type[BasePlugin]] = {
    "intent_fuzzer": IntentFuzzerPlugin,
    "content_provider": ContentProviderPlugin,
    "deeplink_fuzzer": DeepLinkPlugin,
    "broadcast_analyzer": BroadcastPlugin,
    "service_binder": ServiceBinderPlugin,
    "webview_exploiter": WebViewPlugin,
    "task_hijacker": TaskHijackPlugin,
    "fragment_injector": FragmentInjectorPlugin,
    "pending_intent": PendingIntentPlugin,
    "file_provider": FileProviderPlugin,
    "backup_extractor": BackupExtractorPlugin,
    "storage_analyzer": StorageAnalyzerPlugin,
    "attack_chain": AttackChainPlugin,
    "exploit_validator": ExploitValidatorPlugin,
}

# Plugins that run after all others (post-processing)
POST_PROCESS_PLUGINS = ("attack_chain", "exploit_validator")

__all__ = [
    "BasePlugin",
    "PluginCategory",
    "PluginFinding",
    "IntentSpec",
    "PoC",
    "ValidationVerdict",
    "ALL_PLUGINS",
    "POST_PROCESS_PLUGINS",
    "IntentFuzzerPlugin",
    "ContentProviderPlugin",
    "DeepLinkPlugin",
    "BroadcastPlugin",
    "ServiceBinderPlugin",
    "WebViewPlugin",
    "TaskHijackPlugin",
    "FragmentInjectorPlugin",
    "PendingIntentPlugin",
    "FileProviderPlugin",
    "BackupExtractorPlugin",
    "StorageAnalyzerPlugin",
    "AttackChainPlugin",
    "ExploitValidatorPlugin",
]
