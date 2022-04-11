import requests

from typing import Optional, Iterable


class UsersRepo:
    def __init__(self, user_provider_adr: str):
        self.__username_pubkey = {}
        self.__pubkey_username = {}
        self.__provider_adr = user_provider_adr

    def full_update(self):
        num_users_resp = requests.get(f'{self.__provider_adr}/users')
        if not num_users_resp:
            raise ConnectionError('cant connect to the provider')
        num_users = num_users_resp.json()['num_users']
        for i in range(num_users):
            user_res = requests.get(f'{self.__provider_adr}/users/{i}')
            if user_res:
                username = user_res.json()['username']
                pubkey = user_res.json()['pubkey']
                self.__username_pubkey[username] = pubkey
                self.__pubkey_username[pubkey] = username
    
    def get_pubkey(self, username: str) -> Optional[str]:
        if username in self.__username_pubkey:
            return self.__username_pubkey[username]
        self.full_update()
        if username in self.__username_pubkey:
            return self.__username_pubkey[username]
        return None

    def get_username(self, pubkey: str) -> Optional[str]:
        if pubkey in self.__pubkey_username:
            return self.__pubkey_username[pubkey]
        self.full_update()
        if pubkey in self.__pubkey_username:
            return self.__pubkey_username[pubkey]
        return None

    def get_usernames(self) -> Iterable[str]:
        for username in self.__username_pubkey:
            yield username
