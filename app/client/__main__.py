try:
    import PySide6  # noqa: F401
    import httpx  # noqa: F401
    import keyring  # noqa: F401
    import platformdirs  # noqa: F401
    import pydantic  # noqa: F401
    import pydantic_settings  # noqa: F401
except ImportError:
    raise RuntimeError(
        "Missing dependencies. Please install the [client] optional "
        "dependencies to run the syncserver client."
    ) from None


from .main import main

if __name__ == "__main__":
    main()
