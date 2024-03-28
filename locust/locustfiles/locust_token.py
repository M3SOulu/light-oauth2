from locust import HttpUser, task, SequentialTaskSet, TaskSet, tag

import logging
from urllib.parse import urlparse, parse_qs
from hashlib import sha256
from base64 import urlsafe_b64encode
from dataclasses import dataclass, field, InitVar
from os import urandom

from .locust_client import CLIENTS, Client

__all__ = ['OAuthUser']


@dataclass(init=True, repr=True, eq=False)
class OAuthFlow:
    client: InitVar[Client]
    clientId: str = field(init=False, repr=True)
    clientSecret: str = field(init=False, repr=False)
    authorization_code: str = field(default=None, init=False, repr=True)
    access_token: str = field(default=None, init=False, repr=True)
    refresh_token: str = field(default=None, init=False, repr=True)
    PKCE_code_challenge: str = field(default=None, init=False, repr=True)
    PKCE_code_challenge_method: str = field(default=None, init=False, repr=True)
    PKCE_code_verifier: str = field(default=None, init=False, repr=True)

    def __post_init__(self, client: Client):
        self.clientId = client.clientId
        self.clientSecret = client.clientSecret

    def make_pkce(self, *, method: str = 'S256', length: int = 64) -> None:
        self.PKCE_code_verifier = urlsafe_b64encode(urandom(length)).decode('utf-8').rstrip('=')
        self.PKCE_code_challenge_method = method
        if method == 'S256':
            self.PKCE_code_challenge = urlsafe_b64encode(sha256(self.PKCE_code_verifier.encode('utf-8')).digest()).decode('utf-8').rstrip('=')

    def code_request(self, pkce: bool = False) -> dict[str, str]:
        request = {"response_type": "code",
                   "client_id": self.client.clientId,
                   "redirect_uri": "http://localhost:8080/authorization"}
        if pkce:
            request["code_challenge"] = self.PKCE_code_challenge,
            request["code_challenge_method"] = self.PKCE_code_challenge_method
        return request

    def token_request(self, grant_type: str, pkce: bool = False) -> dict[str, str]:
        request = {"grant_type": grant_type}
        if grant_type == 'authorization_code':
            request["code"] = self.authorization_code
            request["redirect_uri"] = "http://localhost:8080/authorization"
        if pkce:
            request["code_verifier"] = self.PKCE_code_verifier
        return request


class OAuthUser(HttpUser):

    host = "https://localhost:6882"

    def on_start(self):
        self.token_host = "https://localhost:6882"
        self.code_host = "https://localhost:6881"
        self.cl = CLIENTS.pop()
        self.oauth = OAuthFlow(self.cl)

    @task(0)
    def change_client(self):
        new_cl = CLIENTS.pop()
        CLIENTS.add(self.cl)
        self.cl = new_cl
        self.oauth = OAuthFlow(new_cl)

    @tag('client_credentials')
    @task(1)
    class ClientCredentialsFlow(TaskSet):

        @tag('correct', '200')
        @task(1)
        def access_token_client_credentials_flow_200(self):
            user: OAuthUser = self.user
            r = self.client.post(f"{user.token_host}/oauth2/token",
                                 data=user.oauth.token_request('client_credentials'),
                                 auth=(user.oauth.clientId, user.oauth.clientSecret),
                                 verify=False,
                                 allow_redirects=False)
            if r.status_code == 200:
                r = r.json()
                access_token = r['access_token']
                user.oauth.access_token = access_token
                logging.info(f"Access Token Client Credentials Flow: ClientId = {user.oauth.clientId},"
                             f"Access Token = {access_token}")
            else:
                r = r.json()
                logging.warning(f"Access Token Client Credentials Flow: Did not get code 200, code is {r['statusCode']}, "
                                f"error code is {r['code']}")

    @tag('authorization_code', 'noPKCE')
    @task(1)
    class AuthorizationCodeFlow(SequentialTaskSet):

        @task(1)
        def access_code(self):
            user: OAuthUser = self.user
            r = self.client.get(f"{user.code_host}/oauth2/code",
                                params=user.oauth.code_request(),
                                auth=('admin', '123456'),
                                verify=False,
                                allow_redirects=False)
            if r.status_code == 302:
                parsed_redirect = urlparse(r.headers['Location'])
                redirect_params = parse_qs(parsed_redirect.query)
                auth_code = redirect_params.get('code')[0]
                user.oauth.authorization_code = auth_code
                logging.info(f"Auth Code: ClientId = {user.oauth.clientId}, Authorization_code = {auth_code}")
            else:
                r = r.json()
                logging.warning(f"Auth Code: Endpoint did not redirect, got code {r['statusCode']}, message {r['message']}")

        @task(1)
        def access_token_authorization_code_flow(self):
            user: OAuthUser = self.user
            r = self.client.post(f"{user.token_host}/oauth2/token",
                                 data=user.oauth.token_request('authorization_code'),
                                 auth=(user.oauth.clientId, user.oauth.clientSecret),
                                 verify=False,
                                 allow_redirects=False)
            if r.status_code == 200:
                r = r.json()
                access_token = r['access_token']
                user.oauth.access_token = access_token
                logging.info(f"Access Token Authorization Code Flow: ClientId = {user.oauth.clientId},"
                             f"Access Token = {access_token}")
            else:
                r = r.json()
                logging.warning(f"Access Token Authorization Code Flow: Did not get code 200, code is {r['statusCode']}, "
                                f"error code is {r['code']}")
            self.interrupt()

    @tag('authorization_code', 'PKCE')
    @task(1)
    class AuthorizationCodeFlowPKCE(SequentialTaskSet):

        def on_start(self):
            self.user.oauth.make_pkce()

        @task(1)
        def access_code_pkce(self):
            user: OAuthUser = self.user
            r = self.client.get(f"{user.code_host}/oauth2/code",
                                params=user.oauth.code_request(pkce=True),
                                auth=('admin', '123456'),
                                verify=False,
                                allow_redirects=False)
            if r.status_code == 302:
                parsed_redirect = urlparse(r.headers['Location'])
                redirect_params = parse_qs(parsed_redirect.query)
                auth_code = redirect_params.get('code')[0]
                user.oauth.authorization_code = auth_code
                logging.info(f"Auth Code PKCE: ClientId = {user.oauth.clientId}, Authorization_code = {auth_code}")
            else:
                r = r.json()
                logging.warning(f"Auth Code PKCE: Endpoint did not redirect, got code {r['statusCode']}, message {r['message']}")

        @task(1)
        def access_token_authorization_code_flow_pkce(self):
            user: OAuthUser = self.user
            r = self.client.post(f"{user.token_host}/oauth2/token",
                                 data=user.oauth.token_request('authorization_code', pkce=True),
                                 auth=(user.oauth.clientId, user.oauth.clientSecret),
                                 verify=False,
                                 allow_redirects=False)
            if r.status_code == 200:
                r = r.json()
                access_token = r['access_token']
                user.oauth.access_token = access_token
                logging.info(f"Access Token Authorization Code Flow PKCE: ClientId = {user.oauth.clientId},"
                             f"Access Token = {access_token}")
            else:
                r = r.json()
                logging.warning(f"Access Token Authorization Code Flow PKCE: Did not get code 200, code is {r['statusCode']}, "
                                f"error code is {r['code']}")
            self.interrupt()
