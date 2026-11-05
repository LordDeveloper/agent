"""Metadata-driven client sync helpers (protocol adapters register by core key)."""

from agent.support.client_sync.registry import adapter_for_core, list_registered_cores

__all__ = ['adapter_for_core', 'list_registered_cores']
