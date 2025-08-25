"""
Internal API endpoints for inter-service communication.

These endpoints are meant to be called only by other services in the Archon system,
not by external clients. They provide internal functionality like credential sharing.
"""

import logging
import os
from typing import Any
from ipaddress import ip_address, ip_network

from fastapi import APIRouter, HTTPException, Request

from ..services.credential_service import credential_service

logger = logging.getLogger(__name__)

# Create router with internal prefix
router = APIRouter(prefix="/internal", tags=["internal"])

"""Simple, flexible IP-based access control for internal endpoints.

By defecto permitimos rangos privados más comunes:
- 127.0.0.0/8 (loopback)
- 10.0.0.0/8 (muchas plataformas/overlays usan 10.x, como Coolify)
- 172.16.0.0/12 (redes Docker típicas)
- 192.168.0.0/16 (privadas)
- 100.64.0.0/10 (CGNAT, algunos entornos de overlay)

Se pueden añadir CIDRs adicionales con la variable de entorno ALLOWED_INTERNAL_CIDRS
como lista separada por comas, por ejemplo: "10.0.0.0/8,172.20.0.0/16".
"""

DEFAULT_ALLOWED_CIDRS = [
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
]


def _get_allowed_cidrs() -> list[str]:
    extra = os.getenv("ALLOWED_INTERNAL_CIDRS", "")
    cidrs = [c.strip() for c in extra.split(",") if c.strip()]
    return DEFAULT_ALLOWED_CIDRS + cidrs


def is_internal_request(request: Request) -> bool:
    """Check if request is from an internal/private source based on client IP/CIDR."""
    client_host = request.client.host if request.client else None

    if not client_host:
        return False

    # Normalize common localhost names
    if client_host in ["localhost"]:
        return True

    try:
        ip = ip_address(client_host)
    except ValueError:
        # If not a plain IP (very unlikely here), deny
        logger.warning(f"Internal check: could not parse client host as IP: {client_host}")
        return False

    for cidr in _get_allowed_cidrs():
        try:
            if ip in ip_network(cidr, strict=False):
                # Log once at INFO for visibility during setup
                logger.info(f"Allowing internal request from {client_host} in {cidr}")
                return True
        except ValueError:
            logger.debug(f"Skipping invalid CIDR in ALLOWED_INTERNAL_CIDRS: {cidr}")

    return False


@router.get("/health")
async def internal_health():
    """Internal health check endpoint."""
    return {"status": "healthy", "service": "internal-api"}


@router.get("/credentials/agents")
async def get_agent_credentials(request: Request) -> dict[str, Any]:
    """
    Get credentials needed by the agents service.

    This endpoint is only accessible from internal services and provides
    the necessary credentials for AI agents to function.
    """
    # Check if request is from internal source
    if not is_internal_request(request):
        logger.warning(f"Unauthorized access to internal credentials from {request.client.host}")
        raise HTTPException(status_code=403, detail="Access forbidden")

    try:
        # Get credentials needed by agents
        credentials = {
            # OpenAI credentials
            "OPENAI_API_KEY": await credential_service.get_credential(
                "OPENAI_API_KEY", decrypt=True
            ),
            "OPENAI_MODEL": await credential_service.get_credential(
                "OPENAI_MODEL", default="gpt-4o-mini"
            ),
            # Model configurations
            "DOCUMENT_AGENT_MODEL": await credential_service.get_credential(
                "DOCUMENT_AGENT_MODEL", default="openai:gpt-4o"
            ),
            "RAG_AGENT_MODEL": await credential_service.get_credential(
                "RAG_AGENT_MODEL", default="openai:gpt-4o-mini"
            ),
            "TASK_AGENT_MODEL": await credential_service.get_credential(
                "TASK_AGENT_MODEL", default="openai:gpt-4o"
            ),
            # Rate limiting settings
            "AGENT_RATE_LIMIT_ENABLED": await credential_service.get_credential(
                "AGENT_RATE_LIMIT_ENABLED", default="true"
            ),
            "AGENT_MAX_RETRIES": await credential_service.get_credential(
                "AGENT_MAX_RETRIES", default="3"
            ),
            # MCP endpoint
            "MCP_SERVICE_URL": f"http://archon-mcp:{os.getenv('ARCHON_MCP_PORT')}",
            # Additional settings
            "LOG_LEVEL": await credential_service.get_credential("LOG_LEVEL", default="INFO"),
        }

        # Filter out None values
        credentials = {k: v for k, v in credentials.items() if v is not None}

        logger.info(f"Provided credentials to agents service from {request.client.host}")
        return credentials

    except Exception as e:
        logger.error(f"Error retrieving agent credentials: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve credentials")


@router.get("/credentials/mcp")
async def get_mcp_credentials(request: Request) -> dict[str, Any]:
    """
    Get credentials needed by the MCP service.

    This endpoint provides credentials for the MCP service if needed in the future.
    """
    # Check if request is from internal source
    if not is_internal_request(request):
        logger.warning(f"Unauthorized access to internal credentials from {request.client.host}")
        raise HTTPException(status_code=403, detail="Access forbidden")

    try:
        credentials = {
            # MCP might need some credentials in the future
            "LOG_LEVEL": await credential_service.get_credential("LOG_LEVEL", default="INFO"),
        }

        logger.info(f"Provided credentials to MCP service from {request.client.host}")
        return credentials

    except Exception as e:
        logger.error(f"Error retrieving MCP credentials: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve credentials")
