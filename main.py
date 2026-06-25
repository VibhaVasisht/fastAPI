from requests import status_codes
from requests import session
from requests import Response
import sys
import secrets
import base64
import hashlib
import hmac
import time
import urllib.parse
from contextlib import asynccontextmanager
from typing import Generator, Annotated, Optional
# pyrefly: ignore [missing-import]
from sqlmodel import Field, Session, SQLModel, create_engine, select
# pyrefly: ignore [missing-import]
from sqlalchemy.pool import StaticPool         
from fastapi import FastAPI, HTTPException, Depends, Request, Form, Header, Request
# pyrefly: ignore [missing-import]
from fastapi import Response as res
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
# pyrefly: ignore [missing-import]
from fastapi.responses import JSONResponse

# Config 
MODE = sys.argv[1] if len(sys.argv) > 1 else "noauth"
assert MODE in ("noauth", "basic", "oauth2", "oauth1"), f"Unknown mode: {MODE}"

import os
GITHUB_CLIENT_ID     = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
TUMBLR_API_KEY       = os.environ.get("TUMBLR_API_KEY", "")
TUMBLR_API_SECRET    = os.environ.get("TUMBLR_API_SECRET", "")

BASIC_USER = "admin"
BASIC_PASS = "secret"

# Mock DB 

class Details(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str
    email: str | None = None

DATABASE_URL = "sqlite://"
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize schema structures in memory
    SQLModel.metadata.create_all(engine)
    yield

# App 

app = FastAPI(title=f"Auth Test [{MODE}]", lifespan=lifespan)

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

@app.get("/details", response_model = list[Details])
def list_items(_=Depends(AUTH)):
    with Session(engine) as sess:
        return sess.exec(select(Details)).all()

@app.post("/details", status_code=201, response_model = Details)
def create_item(item: Details, _=Depends(AUTH)):
    with Session(engine) as sess:
        sess.add(item)
        sess.commit()
        sess.refresh(item)
        return item

@app.put("/details/{details_id}", response_model=Details)
def update_item(details_id: int, item: Details, _=Depends(AUTH)):
    with Session(engine) as sess:
        existing = sess.get(Details, details_id)
        if not existing:
            raise HTTPException(404, "Not found")
        existing.name = item.name
        existing.email = item.email
        sess.add(existing)
        sess.commit()
        sess.refresh(existing)
        return existing

@app.patch("/details/{details_id}", response_model=Details)
def partial_update_item(details_id: int, item: Details, _=Depends(AUTH)):
    with Session(engine) as sess:
        existing = sess.get(Details, details_id)
        if not existing:
            raise HTTPException(404, "Not found")
        update_data = item.dict(exclude_unset=True)
        for key, value in update_data.items():
            setattr(existing, key, value)
        sess.add(existing)
        sess.commit()
        sess.refresh(existing)
        return existing

@app.delete("/details/{details_id}")
def delete_item(details_id: int, _=Depends(AUTH)):
    with Session(engine) as sess:
        existing = sess.get(Details, details_id)
        if not existing:
            raise HTTPException(404, "Not found")
        sess.delete(existing)
        sess.commit()
        return {"deleted": details_id}

@app.head("/details")
def head_items():
    return res(
        status_code=200,
        headers={
            "ETag": '"User Details"',
            "Content-Type": "application/json",
        },
    )

@app.options("/details")
def options_items(_=Depends(AUTH)):
    response = res()
    response.headers["allow"] = "GET,POST,PUT,DELETE,HEAD,OPTIONS"
    return response

@app.post("/echo-form/")
async def echo_form(
    name: Annotated[str, Form(description="name")],
    email: Annotated[str, Form(description="email")],

):
    # Echoes back received fields
    result = {
        "received_fields": {
            "name": name,
            "email": email,
        },
    }

    return JSONResponse(content=result)


@app.post("/echo-text-form/")
async def echo_text_form(
    name: Annotated[str, Form()],
    email: Annotated[str, Form()],
):
    # Accepts x-www-form-urlencoded/text
    return {"name": name, "email": email}


@app.post("/echo-headers/")
async def echo_headers(
    request: Request,
    x_custom_header: Annotated[Optional[str], Header()] = None,
):
    return {
        "sent": {
            "x-custom-header": x_custom_header,
        }
    }

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

# OAuth 1 (Tumblr)

def _parse_oauth_header(header: str) -> dict:
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

@app.get("/auth/tumblr/login")
async def tumblr_login():
    callback = "https://oauth1-d59v.onrender.com/auth/tumblr/callback"
    oauth = OAuth1Session(TUMBLR_API_KEY, client_secret=TUMBLR_API_SECRET, callback_uri=callback)
    r = oauth.fetch_request_token("https://www.tumblr.com/oauth/request_token")
    oauth1_request_tokens[r["oauth_token"]] = r["oauth_token_secret"]
    url = oauth.authorization_url("https://www.tumblr.com/oauth/authorize")
    return RedirectResponse(url)

@app.get("/auth/tumblr/callback")
async def tumblr_callback(oauth_token: str, oauth_verifier: str):
    req_secret = oauth1_request_tokens.pop(oauth_token, None)
    if not req_secret:
        raise HTTPException(400, "Unknown request token")
    oauth = OAuth1Session(TUMBLR_API_KEY, client_secret=TUMBLR_API_SECRET,
                          resource_owner_key=oauth_token,
                          resource_owner_secret=req_secret,
                          verifier=oauth_verifier)
    r = oauth.fetch_access_token("https://www.tumblr.com/oauth/access_token")
    oauth1_tokens[r["oauth_token"]] = r["oauth_token_secret"]
    return {"oauth_token": r["oauth_token"], "oauth_token_secret": r["oauth_token_secret"]}

    url = "https://www.tumblr.com/oauth/access_token"
    params = {
        "oauth_consumer_key": TUMBLR_API_KEY,
        "oauth_token": oauth_token,
        "oauth_verifier": oauth_verifier,
        "oauth_nonce": secrets.token_hex(8),
        "oauth_signature_method": "HMAC-SHA1",
        "oauth_timestamp": str(int(time.time())),
        "oauth_version": "1.0",
    }
    params["oauth_signature"] = _oauth1_signature("GET", url, params, TUMBLR_API_SECRET, req_secret)

    header = "OAuth " + ", ".join(f'{k}="{v}"' for k, v in params.items())
    async with httpx.AsyncClient() as client:
        r = await client.get(url, headers={"Authorization": header})

    parsed = dict(urllib.parse.parse_qsl(r.text))
    access_token  = parsed.get("oauth_token")
    access_secret = parsed.get("oauth_token_secret")
    if not access_token:
        raise HTTPException(400, f"Tumblr error: {r.text}")

    oauth1_tokens[access_token] = access_secret
    return {
        "oauth_token": access_token,
        "oauth_token_secret": access_secret,
    }


if __name__ == "__main__":
    print(f"\n   Mode: {MODE}")
    uvicorn.run(app, host="0.0.0.0", port=8000)