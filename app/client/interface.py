import json
import logging
import httpx

from platformdirs import PlatformDirs
from pydantic import ValidationError

from .models import AccessTokenResponse, AccessTokenError
from ..version import __version__


dirs = PlatformDirs("syncserver-client", "newguy103", version=__version__)

# TODO: Implement a better/simpler log setup
logger: logging.Logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

formatter: logging.Formatter = logging.Formatter(
    '[syncServer-interface]: [%(asctime)s] - [%(levelname)s] - %(message)s', 
    datefmt='%Y-%m-%d %H:%M:%S'
)

stream_handler: logging.StreamHandler = logging.StreamHandler()
stream_handler.setFormatter(formatter)

logger.addHandler(stream_handler)


# TODO: Use async httpx when PySide6 supports the asyncio event loop features
# or learn trio to make this asyncio
class MainClient:
    def __init__(self, authorization: str, server_url: str):
        self.auth_header: str = authorization
        self.server_url: str = server_url

    @classmethod
    def fetch_authorization_header(
        cls, username: str, 
        password: str, server_url: str
    ) -> AccessTokenResponse | AccessTokenError:
        with httpx.Client(timeout=30, follow_redirects=False, base_url=server_url) as client:
            # OAuth2 Specification (https://www.oauth.com/oauth2-servers/access-tokens/password-grant/)
            data = {
                'grant_type': 'password',
                'username': username,
                'password': password
            }

            # Controller should handle it with an error Signal
            try:
                res = client.post(
                    '/api/auth/token',
                    headers={
                        'accept': 'application/json',
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    data=data
                )
                res_data: dict = res.json()

                if res.is_server_error:
                    res.raise_for_status()
            except httpx.HTTPStatusError:
                logger.exception("Internal server error:")
                raise
            except httpx.HTTPError:
                logger.exception("HTTP error:")
                raise
            except json.JSONDecodeError:
                logger.exception(
                    "Data received from server is invalid JSON, response body: %s",
                    res.text
                )
                raise
            except Exception:
                logger.critical(
                    "Unexpected Exception while fetching authorization header, "
                    "response body: %s", res.text,
                    exc_info=True
                )
                raise

        if res.is_client_error:    
            err_model = AccessTokenError(**res_data)
            return err_model
        
        res_model = AccessTokenResponse(**res_data)
        return res_model
    
    def setup(self) -> bool:
        self.client: httpx.Client = httpx.Client(
            headers={
                'accept': 'application/json',
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.auth_header}'
            },
            timeout=30,
            follow_redirects=False,
            base_url=self.server_url
        )

        try:
            auth_resp = self.client.get('/api/auth/test_auth')
            auth_resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            logger.exception("HTTP Status Error, HTTP %d:", exc.response.status_code)
            raise
        except httpx.HTTPError:
            logger.exception("Generic HTTP Error:")
            raise
        except Exception:
            logger.critical("Unexpected error:", exc_info=True)
            raise

        return True

    def close(self):
        self.client.close()


def main(): 
    cl = MainClient('x', 'http://localhost:8000')
    setup_complete, exc = cl.setup()


if __name__ == '__main__':
    main()
