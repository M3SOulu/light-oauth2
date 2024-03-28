from locust import HttpUser, task, SequentialTaskSet, TaskSet, tag

import logging
from urllib.parse import urlparse, parse_qs
from uuid import uuid4
from hashlib import sha256
from base64 import b64encode
from dataclasses import dataclass, field

from .locust_client import CLIENTS, Client

__all__ = ['OAuthUser']


@dataclass(init=True, repr=False, eq=False)
class OAuthFlow:
    client: Client
    authorization_code: str = field(init=False)
    access_token: str = field(init=False)
    refresh_token: str = field(init=False)
    PKCE_code_challenge: bytes = field(init=False)
    PKCE_code_challenge_method: str = field(init=False)
    PKCE_code_verifier: str = field(init=False)

    def make_pkce(self, method='S256'):
        self.PKCE_code_verifier = str(uuid4()) + str(uuid4)
        self.PKCE_code_challenge_method = method
        if method == 'S256':
            self.PKCE_code_challenge = b64encode(sha256(self.PKCE_code_verifier.encode('utf-8')).digest())

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
        cl = CLIENTS.pop()
        self.oauth = OAuthFlow(cl)

    @task(0)
    def change_client(self):
        new_cl = CLIENTS.pop()
        CLIENTS.add(self.oauth.client)
        self.oauth = OAuthFlow(new_cl)

    @tag('client_credentials')
    @task(1)
    class ClientCredentialsFlow(TaskSet):

        @tag('correct', '200')
        @task(1)
        def access_token_client_credentials_flow_200(self):
            user: OAuthUser = self.user
            r = self.client.post(f"{self.token_host}/oauth2/token",
                                 data=user.oauth.token_request('client_credentials'),
                                 auth=(self.oauth.client.clientId, self.oauth.client.clientSecret),
                                 verify=False,
                                 allow_redirects=False)
            if r.status_code == 200:
                r = r.json()
                access_token = r['access_token']
                self.oauth.access_token = access_token
                logging.info(f"Access Token Client Credentials Flow: ClientId = {self.oauth.client.clientId},"
                             f"Access Token = {access_token}")
            else:
                r = r.json()
                logging.warning(f"Access Token Client Credentials Flow: Did not get code 200, code is {r['statusCode']}, "
                             f"error code is {r['code']}")

    @tag('authorization_code')
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
                logging.info(f"Auth Code: ClientId = {user.oauth.client.clientId}, Authorization_code = {auth_code}")
            else:
                logging.warning("Auth Code: Endpoint did not redirect")

        @task(1)
        def access_token_authorization_code_flow(self):
            user: OAuthUser = self.user
            r = self.client.post(f"{user.token_host}/oauth2/token",
                                 data=user.oauth.token_request('authorization_code'),
                                 auth=(user.oauth.client.clientId, user.oauth.client.clientSecret),
                                 verify=False,
                                 allow_redirects=False)
            if r.status_code == 200:
                r = r.json()
                access_token = r['access_token']
                user.oauth.access_token = access_token
                logging.info(f"Access Token Authorization Code Flow: ClientId = {user.oauth.client.clientId},"
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
                logging.info(f"Auth Code: ClientId = {user.oauth.client.clientId}, Authorization_code = {auth_code}")
            else:
                logging.info("Auth Code: Endpoint did not redirect")

        @task(1)
        def access_token_authorization_code_flow_pkce(self):
            user: OAuthUser = self.user
            r = self.client.post(f"{user.token_host}/oauth2/token",
                                 data=user.oauth.token_request('authorization_code', pkce=True),
                                 auth=(user.oauth.client.clientId, user.oauth.client.clientSecret),
                                 verify=False,
                                 allow_redirects=False)
            if r.status_code == 200:
                r = r.json()
                access_token = r['access_token']
                user.oauth.access_token = access_token
                logging.info(f"Access Token Authorization Code Flow: ClientId = {user.client.clientId},"
                             f"Access Token = {access_token}")
            else:
                r = r.json()
                logging.info(f"Access Token Authorization Code Flow: Did not get code 200, code is {r['statusCode']}, "
                             f"error code is {r['code']}")
            self.interrupt()
