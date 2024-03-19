from fastapi import FastAPI

app = FastAPI()

@app.get("/", tags=["Root"])
async def read_root() -> dict:
    return {
        "message": "Hello World"
    }

# app.include_router(NoteRouter, prefix="/note")
