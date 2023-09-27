from uvicorn import run


if __name__ == '__main__':
    run(
        app='offat.api.app:app',
        host="0.0.0.0",
        port=8000,
        workers=2,
        reload=True
    )