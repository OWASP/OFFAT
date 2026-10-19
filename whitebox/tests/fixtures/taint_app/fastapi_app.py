import subprocess

import yaml
from fastapi import Depends, FastAPI
from sqlalchemy import text

app = FastAPI()


def get_db():
    yield None


@app.get("/items/{item_id}")
def read_item(item_id: int, db=Depends(get_db)):
    return db.execute(text(f"SELECT * FROM items WHERE id = {item_id}"))     # SAFE int-typed


@app.get("/lookup")
def lookup(sku: str, db=Depends(get_db)):
    return db.execute(text(f"SELECT * FROM items WHERE sku = '{sku}'"))      # VULN sqli


@app.post("/config")
def load_config(body: str):
    return yaml.load(body)                                                   # VULN yaml


@app.post("/config-safe")
def load_config_safe(body: str):
    return yaml.load(body, Loader=yaml.SafeLoader)                           # SAFE


@app.post("/convert")
async def convert(fmt: str):
    proc = subprocess.run(["convert", "-format", fmt, "in.png"])             # SAFE no shell
    return {"rc": proc.returncode}
