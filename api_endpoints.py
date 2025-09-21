"""Module with optional api_endpoints to use"""

import requests
import logging

from spotify_verification import authkey, short_term_token

logger = logging.getLogger(__name__)

access_token = short_term_token


def get_user_data(access_token):
    logger.info(access_token)
    user = requests.get(
        url="https://api.spotify.com/v1/me",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )
    return user


user = get_user_data(access_token)
print(user.text, user.status_code)
