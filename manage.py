import uvicorn

if __name__ == "__main__":
#   uvicorn.run("api:index", host="0.0.0.0", port=8000, reload=True)
    uvicorn.run("api.index:app")