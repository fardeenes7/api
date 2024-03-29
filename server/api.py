from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import os
import json
import requests
from pydantic import BaseModel
from typing import Annotated

# Create FastAPI instance
app = FastAPI()

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

def _get_microservice_url(microservice: str):
    dict =  {
        "auth": os.getenv("AUTH_BACKEND_URL", "http://0.0.0.0:8001"),
        "media": os.getenv("MEDIA_BACKEND_URL", "http://0.0.0.0:8002"),
    }
    url = dict.get(microservice)
    if not url:
        raise HTTPException(status_code=404, detail="Microservice not found")
    return url


async def get_current_user(request: Request):
    # Call authentication backend to validate token and retrieve user information
    url = f"{str(_get_microservice_url('auth'))}/users/me"
    response = requests.get(url, headers=request.headers)
    response.raise_for_status()  # Raise exception for non-2xx status codes

    # Return raw user data from the response (assuming dictionary format)
    return response.json()


async def _make_request(microservice, path, request: Request, method="GET",  user=None):
    #Retrieve the microservice URL
    try:
        microservice_url = _get_microservice_url(microservice)
    except HTTPException as e:
        raise e

    # retieve the request data
    data = await request.json()
    if user:
        data['user'] = user
    # Forward request to target microservice
    response = requests.request(method, f'{microservice_url}/{path}', json=data, headers=request.headers)
    response.raise_for_status()  # Raise exception for non-2xx status codes
    return response


@app.get("/login")
async def login(request:Request):
    # Implement logic to validate and exchange social auth token with auth backend
    # This is a placeholder, replace with your specific social auth provider integration
    token_header = request.headers.get("Authorization")
    if not token_header:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    if not token_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid token format")
    # Example using a placeholder URL (replace with actual API endpoint)
    url = f"{_get_microservice_url('auth')}/users/me"
    headers = {"Authorization": token_header}  # Example header (adjust based on provider)
    response = requests.get(url, headers=headers)
    response.raise_for_status()  # Raise exception for non-2xx status codes
    # Replace with logic to parse user data and access token from auth backend response
    return response.json()


@app.get("/{microservice}/{path}")
async def handle_dynamic_request(microservice:str, path: str, request: Request, current_user: dict = Depends(get_current_user)):
    try:
        # Forward request to target microservice
        response = await _make_request(microservice, path, request, method="GET", user=current_user)
        return response.json()
    except requests.exceptions.RequestException as e:
        # Handle potential errors during request to microservice
        print(f"Error forwarding request to microservice: {e}")
        return HTTPException(status_code=500, detail="Internal server error")
    

@app.post("/{microservice}/{path}")
async def handle_dynamic_request(microservice:str, path: str, request: Request, current_user: dict = Depends(get_current_user)):
    try:
        # Forward request to target microservice
        response = await _make_request(microservice, path, request, method="POST", user=current_user)
        return response.json()
    except requests.exceptions.RequestException as e:
        # Handle potential errors during request to microservice
        print(f"Error forwarding request to microservice: {e}")
        return HTTPException(status_code=500, detail="Internal server error")
    

@app.put("/{microservice}/{path}")
async def handle_dynamic_request(microservice:str, path: str, request: Request, current_user: dict = Depends(get_current_user)):
    try:
        # Forward request to target microservice
        response = await _make_request(microservice, path, request, method="PUT", user=current_user)
        return response.json()
    except requests.exceptions.RequestException as e:
        # Handle potential errors during request to microservice
        print(f"Error forwarding request to microservice: {e}")
        return HTTPException(status_code=500, detail="Internal server error")
    

@app.delete("/{microservice}/{path}")
async def handle_dynamic_request(microservice:str, path: str, request: Request, current_user: dict = Depends(get_current_user)):
    try:
        # Forward request to target microservice
        response = await _make_request(microservice, path, request, method="DELETE", user=current_user)
        return response.json()
    except requests.exceptions.RequestException as e:
        # Handle potential errors during request to microservice
        print(f"Error forwarding request to microservice: {e}")
        return HTTPException(status_code=500, detail="Internal server error")

