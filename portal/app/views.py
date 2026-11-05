"""Compatibility imports for integrations written before the OPNGate rebuild.

The application implementation lives in app.console. Existing URLs and Python
entry points remain available while deployments move to the new console.
"""
from .console import router
from .console.overview import overview
from .console.clients import clients, label_device
from .console.flow import flow_fragment, _flow_data
from .console.traffic import traffic
from .console.network import dns, vpn
from .console.protection import threats, alerts, ack, audit_page
from .console.api import metrics_api, live_api, live_stream, metrics_csv, healthz
