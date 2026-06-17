import json
from fastapi import FastAPI, Request, HTTPException, status
from pydantic import BaseModel

app = FastAPI(title="Multi-Format Receiver API")

class UserPayload(BaseModel):
    name: str
    email: str
    age: int

@app.post("/submit")
async def handle_multi_format_input(request: Request):
    content_type = request.headers.get("Content-Type", "")
    
    # JSON
    if "application/json" in content_type:
        try:
            raw_data = await request.json()
            # Validate raw dict against Pydantic schema
            validated_data = UserPayload(**raw_data)
            return {"source_format": "JSON", "data": validated_data}
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON format submitted.")
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"Validation failed: {str(e)}")

    # XML
    elif "text/plain" in content_type or "application/xml" in content_type:
        raw_body_bytes = await request.body()
        string_content = raw_body_bytes.decode("utf-8")
        
        return {
            "source_format": "XML",
            "character_count": len(string_content),
            "raw_preview": string_content[:100]
        }

    # --- Fallback: Unsupported Media Types ---
    else:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"Content-Type '{content_type}' is unsupported. Use JSON, Form data, or Plain Text."
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
