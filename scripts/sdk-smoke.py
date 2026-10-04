# /// script
# requires-python = ">=3.11"
# dependencies = ["mcp==2.3.0"]
# ///
"""Exercise a release container with the official OAuth-enabled MCP SDK on Linux.

Run after docker build -t oauth-to-key-mcp-proxy:local .:
    uv run scripts/sdk-smoke.py
Only disposable configuration, containers, and volumes are created.
"""

import argparse
import asyncio
import re
import socket
import subprocess
import tempfile
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx2
import uvicorn
from mcp import Client
from mcp.client.auth import AuthorizationCodeResult, OAuthClientProvider
from mcp.client.streamable_http import streamable_http_client
from mcp.server import MCPServer
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata
from pydantic import AnyUrl

API_KEY = "sdk-smoke-upstream-key"
CALLBACK = "http://127.0.0.1:3030/callback"


def docker(*args: str) -> str:
    return subprocess.check_output(["docker", *args], text=True).strip()


def free_socket() -> socket.socket:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    return listener


class Storage:
    def __init__(self) -> None:
        self.tokens = None
        self.client_info = None

    async def get_tokens(self):
        return self.tokens

    async def set_tokens(self, tokens):
        self.tokens = tokens

    async def get_client_info(self):
        return self.client_info

    async def set_client_info(self, client_info):
        self.client_info = client_info


async def main(image: str, prefix: str) -> None:
    upstream = MCPServer("Real upstream", log_level="ERROR")

    @upstream.tool()
    async def echo(message: str) -> str:
        """Return the supplied message unchanged."""
        return message

    mcp_app = upstream.streamable_http_app()
    seen_keys = []

    async def bearer_only(scope, receive, send):
        if scope["type"] == "http":
            key = dict(scope["headers"]).get(b"authorization")
            seen_keys.append(key)
            if key != f"Bearer {API_KEY}".encode():
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"www-authenticate", b"Bearer")]})
                await send({"type": "http.response.body", "body": b"Unauthorized"})
                return
        await mcp_app(scope, receive, send)

    listener = free_socket()
    upstream_url = f"http://127.0.0.1:{listener.getsockname()[1]}/mcp"
    upstream_server = uvicorn.Server(uvicorn.Config(bearer_only, log_level="error"))
    upstream_task = asyncio.create_task(upstream_server.serve(sockets=[listener]))
    proxy_listener = free_socket()
    origin = f"http://127.0.0.1:{proxy_listener.getsockname()[1]}"
    public_url = f"{origin}{prefix}"
    proxy_listener.close()
    resource = f"{public_url}/mcp"
    name = f"oauth-proxy-smoke-{uuid.uuid4().hex[:12]}"
    volume = f"{name}-data"
    browser_visits = 0
    callback = None

    async def redirect_handler(url: str) -> None:
        nonlocal browser_visits, callback
        browser_visits += 1
        # This simulates the user's browser. The MCP SDK remains unmodified.
        async with httpx2.AsyncClient(follow_redirects=False) as browser:
            page = await browser.get(url)
            page.raise_for_status()
            assert f'action="{prefix}/oauth/authorize"' in page.text
            match = re.search(r'name=ticket value="([^"]+)"', page.text)
            assert match, "Authorization page did not contain a consent ticket"
            form = {"ticket": match[1], "action": "allow"}
            if "name=api_token" in page.text:
                form["api_token"] = API_KEY
            response = await browser.post(f"{public_url}/oauth/authorize", data=form,
                                          headers={"Origin": origin})
            assert response.status_code == 303, response.text
            parameters = parse_qs(urlparse(response.headers["location"]).query)
            callback = AuthorizationCodeResult(code=parameters["code"][0],
                                               state=parameters["state"][0],
                                               iss=parameters["iss"][0])

    async def callback_handler() -> AuthorizationCodeResult:
        assert callback is not None
        return callback

    async def connect(storage: Storage, method: str) -> None:
        metadata = OAuthClientMetadata(client_name="Official MCP SDK smoke test",
                                       redirect_uris=[AnyUrl(CALLBACK)],
                                       token_endpoint_auth_method=method)
        oauth = OAuthClientProvider(server_url=resource, client_metadata=metadata,
                                    storage=storage, redirect_handler=redirect_handler,
                                    callback_handler=callback_handler)
        async with httpx2.AsyncClient(auth=oauth) as http:
            async with Client(streamable_http_client(resource, http_client=http)) as client:
                tools = await client.list_tools()
                assert [tool.name for tool in tools.tools] == ["echo"]
                result = await client.call_tool("echo", {"message": "ordinary OAuth works"})
                assert result.content[0].text == "ordinary OAuth works", result
        assert storage.tokens.access_token != API_KEY

    try:
        with tempfile.TemporaryDirectory(prefix="oauth-proxy-smoke-") as directory:
            config = Path(directory) / "config.toml"
            config.write_text(f'public_url = "{public_url}"\nupstream_url = "{upstream_url}"\n'
                              f'bind = "{urlparse(public_url).netloc}"\ntoken_key_file = "/data/token.key"\n'
                              f'[oauth]\nclient_id = "manual-client"\nredirect_uris = ["{CALLBACK}"]\n')
            docker("volume", "create", volume)
            docker("run", "-d", "--name", name, "--network", "host", "--read-only",
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                   "-v", f"{config}:/etc/mcp-proxy/config.toml:ro,Z",
                   "-v", f"{volume}:/data", image)
            async with httpx2.AsyncClient() as http:
                for _ in range(100):
                    try:
                        response = await http.get(f"{public_url}/healthz")
                        if response.status_code == 200:
                            break
                    except httpx2.HTTPError:
                        pass
                    await asyncio.sleep(0.1)
                else:
                    raise AssertionError("Container did not become ready")
            public = Storage()
            await connect(public, "none")
            docker("restart", "--time", "2", name)
            await connect(public, "none")
            assert browser_visits == 1, "Restart unexpectedly required linking again"
            manual = Storage()
            manual.client_info = OAuthClientInformationFull(client_id="manual-client",
                                                            client_secret=API_KEY,
                                                            redirect_uris=[AnyUrl(CALLBACK)],
                                                            token_endpoint_auth_method="client_secret_post")
            await connect(manual, "client_secret_post")
            assert browser_visits == 2
            assert seen_keys and all(key == f"Bearer {API_KEY}".encode() for key in seen_keys)
            print(f"Official MCP SDK at {prefix or '/'}: discovery, DCR, OAuth, tools/list, tools/call, restart, and manual API-key secret passed.")
    except BaseException:
        subprocess.run(["docker", "logs", name], check=False)
        raise
    finally:
        subprocess.run(["docker", "rm", "-f", name], check=False, stdout=subprocess.DEVNULL)
        subprocess.run(["docker", "volume", "rm", volume], check=False, stdout=subprocess.DEVNULL)
        upstream_server.should_exit = True
        await upstream_task


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="oauth-to-key-mcp-proxy:local")
    parser.add_argument("--prefix", default="", help="Public URL path, e.g. /services/one")
    args = parser.parse_args()
    if args.prefix and not re.fullmatch(r"(?:/[A-Za-z0-9._~-]+)+", args.prefix):
        parser.error("--prefix must be a path with nonempty URL-safe segments")
    asyncio.run(main(args.image, args.prefix))
