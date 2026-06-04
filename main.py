import os
import secrets
import sys
import uuid
# pyrefly: ignore [missing-import]
import httpx
from fastapi import FastAPI, Request, Depends, HTTPException, status, Response
# pyrefly: ignore [missing-import]
from fastapi.responses import RedirectResponse
# pyrefly: ignore [missing-import]
from fastapi.security import HTTPBasic, HTTPBasicCredentials
# pyrefly: ignore [missing-import]
from pydantic import BaseModel
# pyrefly: ignore [missing-import]
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth

AUTH_MODE = "basic"
if "no-auth" in sys.argv:
    AUTH_MODE = "none"
elif "oauth1" in sys.argv:
    AUTH_MODE = "oauth1"
elif "oauth2" in sys.argv:
    AUTH_MODE = "oauth2"

GITHUB_CLIENT_ID = "Ov23ligEIFf6Lr5vA63Z"
GITHUB_CLIENT_SECRET = "da2aa57ed5d6d985cce613ff4c30ce81b09539d0"

MY_OAUTH1_API_KEY = "my_api_key"
MY_OAUTH1_API_SECRET = "my_api_secret"

oauth = OAuth()
oauth.register(
    name='myapi',
    client_id='10afcf852c323f5d614bcf1ba735568c',
    client_secret='0e1f8eeb637585c7c3dfe9de59fa9332c251cc1cb5c1ba2911c9451be4e6dbe9',
    request_token_url='http://127.0.0.1:8000/oauth1/request_token',
    access_token_url='http://127.0.0.1:8000/oauth1/access_token',
    authorize_url='http://127.0.0.1:8000/oauth1/authorize',
    api_base_url='http://127.0.0.1:8000/'
)

security = HTTPBasic(auto_error=False)

sessions = {}

def get_current_username(request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    if request.url.path.startswith("/auth/github") or request.url.path.startswith("/auth/myapi") or request.url.path.startswith("/oauth1/"):
        return None # no username/password required for oauth/login/callback

    if AUTH_MODE == "none":
        return None
        
    if AUTH_MODE in ("oauth1", "oauth2"):
        session_token = request.cookies.get("session_token")
        if not session_token:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                session_token = auth_header.split(" ")[1]

        if not session_token or session_token not in sessions:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated via OAuth.",
            )
        return sessions[session_token]

    if AUTH_MODE == "basic":
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated. Provide basic auth credentials.",
                headers={"WWW-Authenticate": "Basic"},
            )

        correct_username_bytes = b"admin"
        correct_password_bytes = b"secret"
        is_correct_username = secrets.compare_digest(
            credentials.username.encode("utf8"), correct_username_bytes
        )
        is_correct_password = secrets.compare_digest(
            credentials.password.encode("utf8"), correct_password_bytes
        )
        if not (is_correct_username and is_correct_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Basic"},
            )
        return credentials.username

app = FastAPI(dependencies=[Depends(get_current_username)])
app.add_middleware(SessionMiddleware, secret_key=secrets.token_hex(16))

@app.get("/auth/github/login")
def github_login():
    if AUTH_MODE not in ("oauth2", "oauth1"):
        return {"message": f"Current mode is {AUTH_MODE}"}
    return RedirectResponse(f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}")

@app.get("/auth/github/callback")
async def github_callback(code: str, response: Response):
    if AUTH_MODE not in ("oauth2", "oauth1"):
        return {"message": "OAuth2 is disabled."}
        
    async with httpx.AsyncClient() as client:
        token_res = await client.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
            }
        )
        token_data = token_res.json()
        access_token = token_data.get("access_token")
        
        if not access_token:
            raise HTTPException(status_code=400, detail="Failed to get access token from GitHub")
            
        user_res = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        user_data = user_res.json()
        
        # Create a session
        session_token = str(uuid.uuid4())
        sessions[session_token] = user_data.get("login")
        
        # Set cookie (for browsers)
        response.set_cookie(key="session_token", value=session_token, httponly=True)
        
        return {
            "message": f"Successfully authenticated as {user_data.get('login')}", 
            "session_token": session_token,
            "user_data": user_data
        }

@app.get("/auth/myapi/login")
async def myapi_login(request: Request):
    if AUTH_MODE != "oauth1":
        return {"message": f"Current mode is {AUTH_MODE}"}
    redirect_uri = str(request.url_for('myapi_callback'))
    return await oauth.myapi.authorize_redirect(
        request, 
        redirect_uri, 
        oauth_callback=redirect_uri
    )

@app.get("/auth/myapi/callback")
async def myapi_callback(request: Request, response: Response):
    if AUTH_MODE != "oauth1":
        return {"message": "OAuth1 is disabled."}
        
    try:
        token = await oauth.myapi.authorize_access_token(request)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to get access token from MyAPI: {str(e)}")
        
    user_res = await oauth.myapi.get('oauth1/me', token=token)
    user_data = user_res.json()
    
    # Create a session
    session_token = str(uuid.uuid4())
    sessions[session_token] = user_data.get("username")
    
    # Set cookie (for browsers)
    response.set_cookie(key="session_token", value=session_token, httponly=True)
    
    return {
        "message": "Successfully authenticated", 
        "session_token": session_token,
        "user_data": user_data
    }

# Mock OAuth 1.0 Provider Endpoints

@app.post("/oauth1/request_token")
async def mock_request_token():
    return Response(
        content="oauth_token=mock_req_token&oauth_token_secret=mock_req_secret", 
        media_type="application/x-www-form-urlencoded"
    )

@app.get("/oauth1/authorize")
async def mock_authorize(oauth_token: str, oauth_callback: str):
    return RedirectResponse(f"{oauth_callback}?oauth_token={oauth_token}&oauth_verifier=mock_verifier_123")

@app.post("/oauth1/access_token")
async def mock_access_token():
    return Response(
        content="oauth_token=mock_acc_token&oauth_token_secret=mock_acc_secret", 
        media_type="application/x-www-form-urlencoded"
    )

@app.get("/oauth1/me")
async def mock_me():
    return {"username": "mock_oauth1_user"}



# --- Item API ---

items = []

class Item(BaseModel):
    name: str
    description: str = ""

@app.get("/items")
def get_items():
    return {"items": items}

@app.post("/items")
def create_item(item: Item):
    items.append(item)
    return {"message": "Item added", "item": item}

@app.put("/items/{name}")
def update_item(name: str, item: Item):
    for i, existing_item in enumerate(items):
        if existing_item.name == name:
            items[i] = item
            return {"message": "Item updated", "item": item}
    return {"message": "Item not found"}

@app.delete("/items/{name}")
def delete_item(name: str):
    for i, existing_item in enumerate(items):
        if existing_item.name == name:
            items.pop(i)
            return {"message": "Item deleted"}
    return {"message": "Item not found"}    

@app.patch("/items/{name}")
def patch_item(name: str, item: Item):
    for i, existing_item in enumerate(items):
        if existing_item.name == name:
            if item.name:
                items[i].name = item.name
            if item.description:
                items[i].description = item.description
            return {"message": "Item updated", "item": item}
    return {"message": "Item not found"}    

@app.head("/items")
def head_items():
    return {"message": "Head for item"}

@app.options("/items")
def options_items(request: Request):
    methods = set()
    for route in app.routes:
        if getattr(route, "path", None) == request.url.path:
            if getattr(route, "methods", None):
                methods.update(route.methods)
    return {"methods": methods}

if __name__ == "__main__":
    # pyrefly: ignore [missing-import]
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
