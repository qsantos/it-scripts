# inspired from https://www.camiloterevinto.com/post/oauth-pkce-flow-from-python-desktop
import base64
import hashlib
import json
import random
import string
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from sys import exit, stderr
from typing import Tuple
from urllib.parse import parse_qs, urlencode, urlparse
from urrllib.request import urlopen


class OAuthHttpServer(HTTPServer):
    def __init__(self, *args, **kwargs):
        HTTPServer.__init__(self, *args, **kwargs)
        self.authorization_code = ""


class OAuthHttpHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write("<script>window.close();</script>".encode())
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        self.server.authorization_code = qs["code"][0]


def generate_code() -> Tuple[str, str]:
    rand = random.SystemRandom()
    verifier = "".join(rand.choices(string.ascii_letters + string.digits, k=128))

    code_sha_256 = hashlib.sha256(verifier.encode()).digest()
    b64 = base64.urlsafe_b64encode(code_sha_256)
    challenge = b64.decode().rstrip("=")

    return challenge, verifier


def get_access_token(
    authorize_uri: str,
    token_uri: str,
    client_id: str,
    secret: str,
    redirect_port: int,
) -> str:
    # generate challenge and verifier for PKCE
    code_challenge, code_verifier = generate_code()

    # get authorization code
    redirect_uri = f"http://localhost:{redirect_port}/"
    with OAuthHttpServer(("", redirect_port), OAuthHttpHandler) as httpd:
        qs = urlencode({
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "scope": "openid api",
            "state": "",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        })
        webbrowser.open_new(f"{authorize_uri}?{qs}")
        httpd.handle_request()
        auth_code = httpd.authorization_code

    # get token
    data = {
        "code": auth_code,
        "client_id": client_id,
        "grant_type": "authorization_code",
        "scopes": "api",
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    with urlopen(token_uri, data=urlencode(data).encode()) as response:
        resp_data = response.read()
    return json.loads(resp_data)["access_token"]


__ALL__ = ["get_access_token"]
