"""
PhishGuard AI — System Integrations & Diagnostics Router
Exposes runtime diagnostics for security integrations without secret leakage.
Provides both full-suite and individual provider on-demand probes.
"""
from fastapi import APIRouter, HTTPException, Query
from ...services.integrations_service import (
    get_all_integration_diagnostics,
    test_single_provider,
)

router = APIRouter()


@router.get("/integrations")
def list_system_integrations(probe: bool = Query(False, description="Whether to execute live network probes immediately")):
    """
    Return runtime operational status for all security integrations.
    If probe=False, returns current cached state or unverified fallback.
    If probe=True, executes real parallel network and local probes.
    """
    integrations = get_all_integration_diagnostics(run_probe=probe)
    return {
        "status": "ok",
        "count": len(integrations),
        "integrations": integrations,
    }


@router.post("/integrations/test-all")
def test_all_integrations():
    """
    Trigger live diagnostic probes across all 12 security integrations in parallel.
    Updates in-memory runtime cache with fresh latencies and operational state.
    """
    integrations = get_all_integration_diagnostics(run_probe=True)
    return {
        "status": "ok",
        "count": len(integrations),
        "integrations": integrations,
    }


@router.post("/integrations/{provider_id}/test")
def test_individual_integration(provider_id: str):
    """
    Trigger a live diagnostic probe for a single security provider on demand.
    Updates the in-memory cache and returns the updated diagnostic object.
    """
    try:
        result = test_single_provider(provider_id)
        return {
            "status": "ok",
            "provider": result,
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Probe execution error: {type(exc).__name__}")

