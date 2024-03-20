from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import os
import json
import requests
from pydantic import BaseModel

# Create FastAPI instance
app = FastAPI()

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

# Environment variables
auth_backend_url = os.getenv("AUTH_BACKEND_URL", "http://0.0.0.0:8001")
if not auth_backend_url:
    raise ValueError("Missing environment variable AUTH_BACKEND_URL")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{auth_backend_url}/login")


async def get_current_user(token: str = Depends(oauth2_scheme)):
    # Call authentication backend to validate token and retrieve user information
    url = f"{auth_backend_url}/users/me"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    response.raise_for_status()  # Raise exception for non-2xx status codes

    # Return raw user data from the response (assuming dictionary format)
    return response.json()


class SOCIAL_AUTH_DATA(BaseModel):
    provider: str
    token: str



@app.post("/login")
async def login(social_auth_data: SOCIAL_AUTH_DATA):
    # Implement logic to validate and exchange social auth token with auth backend
    # This is a placeholder, replace with your specific social auth provider integration
    social_provider = social_auth_data.provider  # Assuming provider key
    social_token = social_auth_data.token  # Assuming token key

    if not (social_provider and social_token):
        raise HTTPException(
            status_code=400, detail="Missing required fields: provider and token"
        )

    # Example using a placeholder URL (replace with actual API endpoint)
    url = f"{auth_backend_url}/login/social/{social_provider}"
    headers = {"Authorization": f"Bearer {social_token}"}  # Example header (adjust based on provider)
    response = await _make_request(url, method="POST", headers=headers)
    response.raise_for_status()  # Raise exception for non-2xx status codes

    # Replace with logic to parse user data and access token from auth backend response
    return response.json()
    



async def _make_request(url, method="GET", data=None, headers=None):
    # Implement your logic to make requests to other services
    response = requests.request(method, url, json=data, headers=headers)
    response.raise_for_status()  # Raise exception for non-2xx status codes
    return response


@app.get("/{path:path}")
async def handle_dynamic_request(
    path: str, user_data: dict = Depends(get_current_user)
):
    # Dynamically determine target microservice and path based on request path
    # Replace with your logic for mapping paths to microservices (e.g., configuration file)
    microservice_config_path = "microservice_config.json"
    with open(microservice_config_path, "r") as f:
        config = json.load(f)
    target_service = config.get(path)
    if not target_service:
        raise HTTPException(status_code=404, detail="Resource not found")

    # Extract user roles from user data (replace with your logic)
    user_roles = user_data.get("roles", [])  # Assuming "roles" key exists

    # Authorize request based on user roles and configuration
    if not has_permission(user_roles, path, target_service):
        raise HTTPException(status_code=403, detail="Forbidden")

    microservice_url = target_service["url"]

    try:
        # Forward request to target microservice
        response = await _make_request(f"{microservice_url}/{path}")
        return response.json()
    except requests.exceptions.RequestException as e:
        # Handle potential errors during request to microservice
        print(f"Error forwarding request to microservice: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

def has_permission(user_roles: list[str], path: str, target_service: dict) -> bool:
    """
    Checks if the user has permission to access the requested path based on roles.

    Args:
        user_roles: List of user roles obtained from the authentication backend.
        path: The requested API path.
        target_service: A dictionary containing configuration for the target microservice.

    Returns:
        True if the user has permission, False otherwise.
    """

    # Check for "allowed_roles" in the config for the path
    if "allowed_roles" in target_service:
        for role in user_roles:
            if role in target_service["allowed_roles"]:
                return True
        return False

    # Check for role-based permissions within the path config
    if "roles" in target_service:
        # Extract action from the path (e.g., "read" from "/products/read")
        action = path.split("/")[1]  # Replace with more robust logic if needed

        # Check if action exists in role permissions and user has the required role
        return action in target_service["roles"] and any(
            role in user_roles for role in target_service["roles"][action]
        )

    # No permission checks defined, deny access by default
    return False

