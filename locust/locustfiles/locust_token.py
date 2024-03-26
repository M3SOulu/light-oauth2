from locust import HttpUser, task, SequentialTaskSet
from locust.exception import RescheduleTask

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
    PKCE_code_challenge: str = field(init=False)
    PKCE_code_verifier: str = field(init=False)


class OAuthUser(HttpUser):

    host = "https://localhost:6882"

    def on_start(self):
        self.token_host = "https://localhost:6882"
        self.code_host = "https://localhost:6881"
        cl = CLIENTS.pop()
        self.oauth = OAuthFlow(cl)

    @task
    def access_token_client_credentials_flow(self):
        r = self.client.post(f"{self.token_host}/oauth2/token", data={"grant_type": "client_credentials"},
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

    @task
    class AuthorizationCodeFlow(SequentialTaskSet):

        @task
        def access_code(self):
            r = self.client.get(f"{self.user.code_host}/oauth2/code", params={"response_type": "code",
                                                                              "client_id": self.user.oauth.client.clientId,
                                                                              "redirect_uri": "http://localhost:8080/authorization" },
                                auth=('admin', '123456'),
                                verify=False,
                                allow_redirects=False)
            if r.status_code == 302:
                parsed_redirect = urlparse(r.headers['Location'])
                redirect_params = parse_qs(parsed_redirect.query)
                auth_code = redirect_params.get('code')[0]
                self.user.oauth.authorization_code = auth_code
                logging.info(f"Auth Code: ClientId = {self.user.oauth.client.clientId}, Authorization_code = {auth_code}")
            else:
                logging.warning("Auth Code: Endpoint did not redirect")

        @task
        def access_token_authorization_code_flow(self):
            r = self.client.post(f"{self.user.token_host}/oauth2/token", data={"grant_type": "client_credentials",
                                                                               "code": self.user.oauth.authorization_code,
                                                                               "redirect_uri": "http://localhost:8080/authorization"},
                                 auth=(self.user.oauth.client.clientId, self.user.oauth.client.clientSecret),
                                 verify=False,
                                 allow_redirects=False)
            if r.status_code == 200:
                r = r.json()
                access_token = r['access_token']
                self.user.oauth.access_token = access_token
                logging.info(f"Access Token Authorization Code Flow: ClientId = {self.user.oauth.client.clientId},"
                             f"Access Token = {access_token}")
            else:
                r = r.json()
                logging.warning(f"Access Token Authorization Code Flow: Did not get code 200, code is {r['statusCode']}, "
                             f"error code is {r['code']}")
            self.interrupt()

    @task(1)
    class AuthorizationCodeFlowPKCE(SequentialTaskSet):

        def on_start(self):
            try:
                self.user.cl = CLIENTS.pop()
            except KeyError:
                self.interrupt()
            self.code_verifier = str(uuid4()) + str(uuid4)
            self.code_challenage = b64encode(sha256(self.code_verifier.encode('utf-8')).digest())

        @task(1)
        def access_code_pkce(self):
            r = self.client.get(
                f"{self.user.code_host}/oauth2/code", params={
                    "response_type": "code",
                    "client_id": self.user.cl.clientId,
                    "redirect_uri": "http://localhost:8080/authorization"
                },
                auth=('admin', '123456'),
                verify=False,
                allow_redirects=False)
            if r.status_code == 302:
                parsed_redirect = urlparse(r.headers['Location'])
                redirect_params = parse_qs(parsed_redirect.query)
                self.user.auth_code = redirect_params.get('code')[0]
                logging.info(f"Auth Code: ClientId = {self.user.cl.clientId}, Authorization_code = {self.user.auth_code}")
            else:
                logging.info("Auth Code: Endpoint did not redirect")

        @task
        def access_token_authorization_code_flow_pkce(self):
            r = self.client.post(
                f"{self.user.token_host}/oauth2/token", data={
                    "grant_type": "client_credentials",
                    "code": self.user.auth_code,
                    "redirect_uri": "http://localhost:8080/authorization"
                },
                auth=(self.user.cl.clientId, self.user.cl.clientSecret),
                verify=False,
                allow_redirects=False)
            if r.status_code == 200:
                r = r.json()
                self.user.access_token = r['access_token']
                logging.info(
                    f"Access Token Authorization Code Flow: ClientId = {self.user.cl.clientId}, Access Token = {self.user.access_token}")
            else:
                r = r.json()
                logging.info(f"Access Token Authorization Code Flow: Did not get code 200, code is {r['statusCode']}, "
                             f"error code is {r['code']}")
            self.user.auth_code = None
            self.interrupt()

        def on_stop(self):
            CLIENTS.add(self.user.cl)
