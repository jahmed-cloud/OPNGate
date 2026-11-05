"""OPNGate console application, composed from focused workspace routers."""
from fastapi import APIRouter
from . import api, clients, flow, network, overview, protection, traffic

router = APIRouter()
for workspace in (overview, clients, flow, traffic, network, protection, api):
    router.include_router(workspace.router)
