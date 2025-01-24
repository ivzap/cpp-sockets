from fastapi import FastAPI
import time
# Example user data
fake_users_db = [
    {"id": 1, "name": "Alice"},
    {"id": 2, "name": "Bob"},
    {"id": 3, "name": "Charlie"},
]
app = FastAPI()

@app.get("/")
async def read_root():
    return {"message": "Hello, Secure World!"}

@app.get("/users/{user_id}", response_model=dict)
async def get_user(user_id: int):
    # Search for the user by ID
    user = next((user for user in fake_users_db if user["id"] == user_id), None)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


if __name__ == "__main__":
    import uvicorn
    # Run the server with SSL
    uvicorn.run(app, host="0.0.0.0", port=8000, ssl_keyfile="key.pem", ssl_certfile="cert.pem")
