"""Read-only Orchestrator integration (Phase 2).

Nothing in this package knows an Orchestrator endpoint, header name or field
name. All of that is data in a per-version mapping file
(``deploy/orchestrator/mapping.<version>.yaml``), filled from the Swagger/OpenAPI
export of that Orchestrator release with ``buffmon-orch-discover``.
"""
