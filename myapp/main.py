from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# from routers import creature, explorer, game, user
from routers import user, auth
from models.database import Base, engine
from services import oauth2_service

Base.metadata.create_all(bind=engine) 

# admin = oauth2_service.create_admin_user()
# print(f"Admin user created: {admin.to_dict()}")

app = FastAPI()

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# app.include_router(explorer.router)
# app.include_router(creature.router)
# app.include_router(game.router)
app.include_router(user.router)
app.include_router(auth.router)

# if __name__ == "__main__":
#     import uvicorn

#     uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
