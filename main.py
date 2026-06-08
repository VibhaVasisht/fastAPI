"""
modes:
noauth
basic
oauth2
oauth1
"""

import sys
import secrets
import base64
import hashlib
import hmac
import time
import urllib.parse         
from fastapi import FastAPI, HTTPException, Depends, Request
# pyrefly: ignore [missing-import]
from fastapi.responses import RedirectResponse
# pyrefly: ignore [missing-import]
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2AuthorizationCodeBearer
# pyrefly: ignore [missing-import]
from pydantic import BaseModel
# pyrefly: ignore [missing-import]
import httpx
# pyrefly: ignore [missing-import]
import uvicorn

# Config 
MODE = sys.argv[1] if len(sys.argv) > 1 else "noauth"
assert MODE in ("noauth", "basic", "oauth2", "oauth1"), f"Unknown mode: {MODE}"

import os
GITHUB_CLIENT_ID     = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
TRELLO_API_KEY       = os.environ.get("TRELLO_API_KEY", "")
TRELLO_API_SECRET    = os.environ.get("TRELLO_API_SECRET", "")

BASIC_USER = "admin"
BASIC_PASS = "secret"

# Mock DB 

class Item(BaseModel):
    name: str
    description: str

db: dict[int, Item] = {
    1: Item(name="Widget", description="A useful widget"),
    2: Item(name="Gadget", description="A cool gadget"),
}
next_id = 3

# App 

app = FastAPI(title=f"Auth Test [{MODE}]")

# Auth dependencies

def no_auth(): pass

# Basic auth
security = HTTPBasic()
def basic_auth(creds: HTTPBasicCredentials = Depends(security)):
    ok = (
        secrets.compare_digest(creds.username, BASIC_USER) and
        secrets.compare_digest(creds.password, BASIC_PASS)
    )
    if not ok:
        raise HTTPException(401, "Bad credentials", headers={"WWW-Authenticate": "Basic"})

# OAuth2 
oauth2_tokens: dict[str, str] = {}
oauth2_states: set[str] = set()

def oauth2_auth(request: Request):
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if token not in oauth2_tokens:
        raise HTTPException(401, "Missing or invalid Bearer token")

# OAuth1
oauth1_tokens: dict[str, str] = {}
oauth1_request_tokens: dict[str, str] = {}

def oauth1_auth(request: Request):
    auth = request.headers.get("Authorization", "")
    if "oauth_token" not in auth:
        raise HTTPException(401, "Missing OAuth1 header")
    token = _parse_oauth_header(auth).get("oauth_token", "")
    if token not in oauth1_tokens:
        raise HTTPException(401, "Invalid oauth_token")

# Pick the right dependency
AUTH = {
    "noauth": no_auth,
    "basic":  basic_auth,
    "oauth2": oauth2_auth,
    "oauth1": oauth1_auth,
}[MODE]

# CRUD routes

@app.get("/items")
def list_items(_=Depends(AUTH)):
    return db

@app.post("/items", status_code=201)
def create_item(item: Item, _=Depends(AUTH)):
    global next_id
    db[next_id] = item
    nid = next_id; next_id += 1
    return {"id": nid, **item.model_dump()}

@app.put("/items/{item_id}")
def update_item(item_id: int, item: Item, _=Depends(AUTH)):
    if item_id not in db:
        raise HTTPException(404, "Not found")
    db[item_id] = item
    return {"id": item_id, **item.model_dump()}

@app.delete("/items/{item_id}")
def delete_item(item_id: int, _=Depends(AUTH)):
    if item_id not in db:
        raise HTTPException(404, "Not found")
    del db[item_id]
    return {"deleted": item_id}

@app.head("/items")
def head_items(_=Depends(AUTH)):
    return {}  

@app.options("/items")
def options_items(_=Depends(AUTH)):
    return {"allow": "GET,POST,PUT,DELETE,HEAD,OPTIONS"}

# OAuth 2 (GitHub)

@app.get("/auth/github/login")
def github_login():
    state = secrets.token_urlsafe(16)
    oauth2_states.add(state)
    url = (
        "https://github.com/login/oauth/authorize"
        f"?client_id={GITHUB_CLIENT_ID}&scope=read:user&state={state}"
    )
    return RedirectResponse(url)

@app.get("/auth/github/callback")
async def github_callback(code: str, state: str):
    if state not in oauth2_states:
        raise HTTPException(400, "Bad state")
    oauth2_states.discard(state)

    async with httpx.AsyncClient() as client:
        r = await client.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={"client_id": GITHUB_CLIENT_ID, "client_secret": GITHUB_CLIENT_SECRET, "code": code},
        )
        data = r.json()
    access_token = data.get("access_token")
    if not access_token:
        raise HTTPException(400, f"GitHub error: {data}")

    oauth2_tokens[access_token] = "github_user"
    return {"bearer_token": access_token, "usage": "Add as: Authorization: Bearer <token>"}

# OAuth 1 (Trello)

def _parse_oauth_header(header: str) -> dict:
    """Parse 'OAuth key="val", ...' into a dict."""
    result = {}
    for part in header.replace("OAuth ", "").split(","):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            result[k.strip()] = v.strip().strip('"')
    return result

def _oauth1_signature(method, url, params: dict, consumer_secret: str, token_secret: str = "") -> str:
    sorted_params = "&".join(f"{urllib.parse.quote(k,'')}"
                             f"={urllib.parse.quote(str(v),'')}"
                             for k, v in sorted(params.items()))
    base = "&".join([
        method.upper(),
        urllib.parse.quote(url, ""),
        urllib.parse.quote(sorted_params, ""),
    ])
    signing_key = f"{urllib.parse.quote(consumer_secret,'')}&{urllib.parse.quote(token_secret,'')}"
    sig = hmac.new(signing_key.encode(), base.encode(), hashlib.sha1).digest()
    return base64.b64encode(sig).decode()

from requests_oauthlib import OAuth1Session

@app.get("/auth/trello/login")
async def trello_login():
    callback = "http://localhost:8000/auth/trello/callback"
    oauth = OAuth1Session(TRELLO_API_KEY, client_secret=TRELLO_API_SECRET, callback_uri=callback)
    r = oauth.fetch_request_token("https://trello.com/1/OAuthGetRequestToken")
    oauth1_request_tokens[r["oauth_token"]] = r["oauth_token_secret"]
    url = oauth.authorization_url("https://trello.com/1/OAuthAuthorizeToken")
    return RedirectResponse(url)

@app.get("/auth/trello/callback")
async def trello_callback(oauth_token: str, oauth_verifier: str):
    req_secret = oauth1_request_tokens.pop(oauth_token, None)
    if not req_secret:
        raise HTTPException(400, "Unknown request token")
    oauth = OAuth1Session(TRELLO_API_KEY, client_secret=TRELLO_API_SECRET,
                          resource_owner_key=oauth_token,
                          resource_owner_secret=req_secret,
                          verifier=oauth_verifier)
    r = oauth.fetch_access_token("https://trello.com/1/OAuthGetAccessToken")
    oauth1_tokens[r["oauth_token"]] = r["oauth_token_secret"]
    return {"oauth_token": r["oauth_token"], "oauth_token_secret": r["oauth_token_secret"]}

    url = "https://trello.com/1/OAuthGetAccessToken"
    params = {
        "oauth_consumer_key": TRELLO_API_KEY,
        "oauth_token": oauth_token,
        "oauth_verifier": oauth_verifier,
        "oauth_nonce": secrets.token_hex(8),
        "oauth_signature_method": "HMAC-SHA1",
        "oauth_timestamp": str(int(time.time())),
        "oauth_version": "1.0",
    }
    params["oauth_signature"] = _oauth1_signature("GET", url, params, TRELLO_API_SECRET, req_secret)

    header = "OAuth " + ", ".join(f'{k}="{v}"' for k, v in params.items())
    async with httpx.AsyncClient() as client:
        r = await client.get(url, headers={"Authorization": header})

    parsed = dict(urllib.parse.parse_qsl(r.text))
    access_token  = parsed.get("oauth_token")
    access_secret = parsed.get("oauth_token_secret")
    if not access_token:
        raise HTTPException(400, f"Trello error: {r.text}")

    oauth1_tokens[access_token] = access_secret
    return {
        "oauth_token": access_token,
        "oauth_token_secret": access_secret,
        "usage": "Build the Authorization header in Postman using OAuth 1.0 with these credentials.",
    }

# Entry point

if __name__ == "__main__":
    print(f"\n   Mode: {MODE}")
    if MODE == "oauth2":
        print("   1. Open http://localhost:8000/auth/github/login in your browser")
        print("   2. Copy the bearer_token from the callback JSON")
        print("   3. Use it in Postman: Authorization → Bearer Token\n")
    if MODE == "oauth1":
        print("   1. Open http://localhost:8000/auth/trello/login in your browser")
        print("   2. Copy oauth_token + oauth_token_secret from the callback JSON")
        print("   3. Use them in Postman: Authorization → OAuth 1.0\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)