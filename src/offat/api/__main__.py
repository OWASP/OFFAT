from uvicorn import run
import importlib.resources


def get_offat_installation_dir():
    try:
        # For non-editable installation
        return importlib.resources.files('offat')
    except ImportError:
        # For editable installation (pip install -e .)
        return importlib.resources.files('.')


def start():
    installation_dir = get_offat_installation_dir()
    run(
        app='offat.api.app:app',
        host="0.0.0.0",
        port=8000,
        workers=2,
        reload=True,
        reload_dirs=[installation_dir],
    )


if __name__ == '__main__':
    start()
