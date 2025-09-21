"""Module ready in parameters from a yaml file and pulls the auth-token from spotify"""

import requests
import os
import base64
import logging
import yaml
import urllib.parse, secrets, webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer


logging.basicConfig(level=logging.INFO, format="%(levelname)s, %(lineno)s, %(message)s")
logger = logging.getLogger(__name__)

AUTH_URL = "https://accounts.spotify.com/authorize"
TOKEN_URL = "https://accounts.spotify.com/api/token"
config_file = os.environ.get("CONFIG_FILES")
config_file_name = "spotify.yaml"
parameter = {"client_id": 0, "client_secret": 0, "redirect_uri": 0}
STATE = secrets.token_urlsafe(16)


def read_yaml(parameter):
    """read yaml file from %PATH "CONFIG_FILES and provide inputs"""
    params = {}
    if config_file is None:
        logger.info("CONFIG_FILES is not set")
    else:
        file_path = os.path.join(config_file, config_file_name)
        logger.info("File_path is: %s", file_path)
        if os.path.isfile(file_path):
            with open(file_path, "r", encoding="utf-8") as file:
                data = yaml.safe_load(file)
                for i in parameter:
                    if i in data:
                        params[i] = data[i]
        else:
            logger.info("Filepath is wrong %s", file_path)
    if not params:
        logger.info("Parameters not in file")
    return params


def authkey(parameter: dict, TOKEN_URL) -> dict:
    params = read_yaml(parameter)
    authorization = f'{params["client_id"]}:{params["client_secret"]}'
    authorization = authorization.encode("utf-8")
    authorization = base64.b64encode(authorization).decode("ascii")
    logger.info(authorization)

    auth_token = requests.post(
        url=TOKEN_URL,
        headers={
            "Authorization": f"Basic {authorization}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data={"grant_type": "client_credentials"},
    )
    return auth_token


short_term_token = "BQAyrwDjj61BExol7QRJCnNXbJ0uy2AyejBFVYwV1Zld7XsZB-aTrculQLwTHYqZPSafg-GXhrhH2QU3GLkJNEU-YSaWqhsydDgvSPkxAA41sm1rHxOlu1bb-ajtq4xIczjtysG4lbI"


def get_authorize_url(parameter, AUTH_URL, STATE):
    params = read_yaml(parameter)
    q = {
        "client_id": params["client_id"],
        "response_type": "code",
        "redirect_uri": params["redirect_uri"],
        "scope": "user-read-private user-read-email",
        "state": STATE,
    }
    return f"{AUTH_URL}?{urllib.parse.urlencode(q)}"


def exchange_code_for_tokens(parameter, TOKEN_URL, code):
    params = read_yaml(parameter)
    response = requests.post(
        TOKEN_URL,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": params["redirect_uri"],
        },
        auth=(params["client_id"], params["client_secret"]),
    )
    return response.json()


def get_user(user_access_token: str) -> dict:
    response = requests.get(
        "https://api.spotify.com/v1/me",
        headers={"Authorization": f"Bearer {user_access_token}"},
    )
    return response.json()


if __name__ == "__main__":
    auth_url = get_authorize_url(parameter, AUTH_URL, STATE)
    params = read_yaml(parameter)
    parsed = urllib.parse.urlparse(auth_url)
    print(auth_url, parsed)
    webbrowser.open(auth_url)
    code_box = {"code": None, "state": None}

    class CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != urllib.parse.urlparse(params["redirect_uri"]).path:
                self.send_response(404)
                self.end_headers()
                return
            qs = urllib.parse.parse_qs(parsed.query)
            code_box["code"] = (qs.get("code") or [""])[0]
            code_box["state"] = (qs.get("state") or [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Alles gut! Du kannst dieses Fenster schliessen.")

        def log_message(self, *args):  # ruhig
            pass

    # Port/Host aus redirect_uri ableiten (z.B. 127.0.0.1:8888)
    parsed_cb = urllib.parse.urlparse(params["redirect_uri"])
    host = parsed_cb.hostname or "127.0.0.1"
    port = parsed_cb.port or 80

    print(f"Warte auf Redirect unter {host}:{port}{parsed_cb.path} ...")
    HTTPServer((host, port), CallbackHandler).handle_request()
    tokens = exchange_code_for_tokens(parameter, TOKEN_URL, code_box["code"])
    access_token_user = tokens["access_token"]
