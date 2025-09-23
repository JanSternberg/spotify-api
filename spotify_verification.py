"""Module ready in parameters from a yaml file and pulls the auth-token from spotify"""

import requests
import os
import base64
import logging
import yaml
import urllib.parse, secrets, webbrowser
from typing import Dict, List
from http.server import BaseHTTPRequestHandler, HTTPServer


logging.basicConfig(level=logging.INFO, format="%(levelname)s, %(lineno)s, %(message)s")
logger = logging.getLogger(__name__)

AUTH_URL = "https://accounts.spotify.com/authorize"
TOKEN_URL = "https://accounts.spotify.com/api/token"
config_file = os.environ.get("CONFIG_FILES")
config_file_name = "spotify.yaml"
jans_parameter = {"jans_client_id": 0, "jans_client_secret": 0, "alls_redirect_uri": 0}
patricia_parameter = {
    "patricia_client_id": 0,
    "patricia_client_secret": 0,
    "alls_redirect_uri": 0,
}
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
                        j = i.split("_")
                        j = f"{j[1]}_{j[2]}"
                        params[j] = data[i]
                    else:
                        print(i)
                        params[i] = i
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
    auth_token = requests.post(
        url=TOKEN_URL,
        headers={
            "Authorization": f"Basic {authorization}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data={"grant_type": "client_credentials"},
    )
    return auth_token


def get_authorize_url(parameter, AUTH_URL, STATE):
    params = parameter
    q = {
        "client_id": params["client_id"],
        "response_type": "code",
        "redirect_uri": params["redirect_uri"],
        "scope": "user-library-read user-read-private user-read-email playlist-modify-public playlist-modify-private",
        "state": STATE,
        "show_dialog": "true",
    }
    return f"{AUTH_URL}?{urllib.parse.urlencode(q)}"


def exchange_code_for_tokens(parameter, TOKEN_URL, code):
    params = parameter
    response = requests.post(
        TOKEN_URL,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": params["redirect_uri"],
        },
        auth=(params["client_id"], params["client_secret"]),
    )
    logging.info("echange_code_for_tokens")
    return response.json()


def get_user(user_access_token: str) -> dict:
    response = requests.get(
        url="https://api.spotify.com/v1/me",
        headers={"Authorization": f"Bearer {user_access_token}"},
    )
    return response.json()


def get_users_playlist(user_id: str, user_access_token: str) -> dict:
    response = requests.get(
        url=f"https://api.spotify.com/v1/users/{user_id}/playlists",
        headers={"Authorization": f"Bearer {user_access_token}"},
    )
    response.raise_for_status()
    print(response.json())
    return response.json()


def get_playlists_items(
    playlist_id: str,
    user_access_token: str,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    url = f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks"
    response = requests.get(
        url=url,
        headers={
            "Authorization": f"Bearer {user_access_token}",
        },
        params={
            "limit": limit,
            "offset": offset,
            "fields": "items(track(uri, name)), offset",
        },
    )
    response.raise_for_status()
    return response.json()


def get_all_playlists_items(playlist_id: str, user_access_token: str) -> dict:
    offset = 0
    full_playlist = []
    while True:
        page = get_playlists_items(playlist_id, user_access_token, offset=offset)
        items = page.get("items", [])
        full_playlist.extend(items)
        if not page.get("next"):
            break
        offset = page["offset"]
    return full_playlist


def create_playlist(
    user_id: str,
    user_access_token: str,
    name_of_playlist: str = "Princess",
) -> str:
    response = requests.post(
        url=f"https://api.spotify.com/v1/users/{user_id}/playlists",
        json={
            "name": name_of_playlist,
            "description": "New Playlist for Patricia to have all songs",
        },
        headers={
            "Authorization": f"Bearer {user_access_token}",
            "Content-Type": "application/json",
        },
    )
    logger.info("Created new Playlist. Name: %s", name_of_playlist)
    return response.json()


def add_items_to_playlist(
    playlist_id: str, user_access_token: str, uris: list[str]
) -> dict:
    response = requests.post(
        url=f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks",
        headers={
            "Authorization": f"Bearer {user_access_token}",
            "Content-Type": "application/json",
        },
        json={
            "uris": uris,
        },
    )
    return response.json()


class CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != urllib.parse.urlparse(copy_to_params["redirect_uri"]).path:
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


def get_users_saved_tracks(
    user_access_token: str, limit: int = 40, offset: str = 0
) -> dict:
    full_playlist = []
    offset = offset
    url = "https://api.spotify.com/v1/me/tracks"
    while True:
        response = requests.get(
            url=url,
            headers={
                "Authorization": f"Bearer {user_access_token}",
                "Accept": "application/json",
            },
            params={
                "limit": limit,
                "offset": offset,
            },
        )
        items = response.json()["items"]
        for track in items:
            full_playlist.append(track["track"]["uri"])
        url = response.json()["next"]
        if url is None:
            break
    response.raise_for_status()
    return full_playlist


def get_all_users_liked_songs(user_access_token, limit, offset) -> dict:
    all_songs = {}
    songs = "asdf"
    pass


def write_stuff(name_of_list: str, data: list):
    with open(name_of_list, mode="a", encoding="utf-8") as file:
        file.write("Track:  \n")
        for track in data:
            file.write(f"- {str(track)}\n")


def read_songs_yaml():
    with open("patricias_loved_songs.yaml", "r") as file:
        data = yaml.safe_load(file)
        return data


def add_items_to_playlist(
    playlist_id: str, uris: Dict[str, List[str]], user_access_token
):
    repeats = int(len(uris["tracks"]) / 100) + 1
    chunks = 100
    tracks = uris["tracks"]
    for i in range(repeats):
        start = i * chunks
        end = start + chunks
        batch = tracks[start:end]
        response = requests.post(
            url=f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks",
            json={
                "uris": batch,
            },
            headers={
                "Authorization": f"Bearer {user_access_token}",
                "Content-Type": "application/json",
            },
        )
    return response.text


if __name__ == "__main__":
    copy_to_params = read_yaml(jans_parameter)
    copy_from_params = read_yaml(patricia_parameter)
    code_box = {"code": None, "state": None}
    logger.info(copy_to_params)

    auth_url = get_authorize_url(copy_to_params, AUTH_URL, STATE)
    logger.info(auth_url)
    parsed = urllib.parse.urlparse(auth_url)
    webbrowser.open(auth_url)

    # Port/Host aus redirect_uri ableiten (z.B. 127.0.0.1:8888)
    parsed_cb = urllib.parse.urlparse(copy_to_params["redirect_uri"])
    host = parsed_cb.hostname or "127.0.0.1"
    port = parsed_cb.port or 80

    HTTPServer((host, port), CallbackHandler).handle_request()
    tokens = exchange_code_for_tokens(copy_to_params, TOKEN_URL, code_box["code"])
    logger.info(tokens)
    user_access_token = tokens["access_token"]
    user_data = get_user(user_access_token)
    user_id = user_data["id"]
    logger.info(user_id)
    user_access_token_auth = authkey(copy_to_params, TOKEN_URL)
    # songs = get_users_saved_tracks(user_access_token)
    # write_stuff("patricias_loved_songs", songs)
    playlist = create_playlist(user_id, user_access_token)
    logger.info(playlist)
    test = add_items_to_playlist(
        playlist_id=playlist["id"],
        uris=read_songs_yaml(),
        user_access_token=user_access_token,
    )
    print(test)
    print("success bitch!")
