#!/usr/bin/env python3
"""
PhishGuard AI — Manual Real-Integration Diagnostic CLI Operation
Runs real runtime probes against all security integrations.
Zero secret exposure. Prints operational SOC status table.

Usage:
    python backend/scripts/diagnose_integrations.py
"""
import sys
import os

# Ensure UTF-8 output on Windows terminals
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Ensure backend root is on sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.services.integrations_service import get_all_integration_diagnostics

def run_diagnostics():
    print("=" * 80)
    print(" PHISHGUARD AI — REAL-TIME INTEGRATION DIAGNOSTICS")
    print(" Operational Runtime Probing Mode: Live Verification (Zero Simulated Data)")
    print("=" * 80)
    print()

    print("[*] Probing all security integrations in parallel...")
    results = get_all_integration_diagnostics(run_probe=True)
    print(f"[+] Probed {len(results)} integrations successfully.\n")

    # Critical Integrations
    print("-" * 80)
    print(" CRITICAL INTEGRATIONS")
    print("-" * 80)
    critical_items = [r for r in results if r.get("critical")]
    for item in critical_items:
        name = item["name"]
        status = item["status"]
        cfg = "YES" if item.get("configured") else "NO"
        tested = "YES" if item.get("tested") else "NO"
        lat = f"{item['latency_ms']} ms" if item.get("latency_ms") is not None else "-"
        print(f"  * {name:<16} Status: {status:<18} Configured: {cfg:<4} Probe: {tested:<4} Latency: {lat}")
        if name == "Splunk HEC":
            print(f"      TCP: {item.get('tcp', '-')} | HEC Health: {item.get('hec_health', '-')} | Auth: {item.get('authentication', '-')} | Event: {item.get('test_event', '-')}")
            if item.get("ack_status"):
                print(f"      ACK: {item.get('ack_status')}")
        elif item.get("real_probe"):
            print(f"      Probe Result: {item.get('real_probe')}")
        if item.get("details"):
            print(f"      Details: {item['details']}")
        if item.get("error_message"):
            print(f"      Safe Error: {item['error_message']}")
        print()

    # Secondary Integrations
    print("-" * 80)
    print(" SECONDARY INTEGRATIONS")
    print("-" * 80)
    secondary_items = [r for r in results if not r.get("critical")]
    for item in secondary_items:
        name = item["name"]
        status = item["status"]
        cfg = "YES" if item.get("configured") else "NO"
        tested = "YES" if item.get("tested") else "NO"
        lat = f"{item['latency_ms']} ms" if item.get("latency_ms") is not None else "-"
        print(f"  * {name:<16} Status: {status:<18} Configured: {cfg:<4} Tested: {tested:<4} Latency: {lat}")
        if item.get("details"):
            print(f"      Details: {item['details']}")
        if item.get("error_message"):
            print(f"      Safe Error: {item['error_message']}")

    print()
    print("=" * 80)
    print(" End of Diagnostics Report — Zero secrets exposed")
    print("=" * 80)

if __name__ == "__main__":
    run_diagnostics()
