from uvicorn import run

def start():
    run(
        app='offat.api.app:app',
        host="0.0.0.0",
        port=8000,
        workers=2,
        reload=True
    )

if __name__ == '__main__':
    start()