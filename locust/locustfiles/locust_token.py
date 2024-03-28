from .mylogging import get__name__

from locust import HttpUser, task, SequentialTaskSet, TaskSet, tag

import logging
from urllib.parse import urlparse, parse_qs
from hashlib import sha256
from base64 import urlsafe_b64encode
from dataclasses import dataclass, field, InitVar
from os import urandom
from time import sleep

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

    def reset_oauth(self) -> None:
        self.authorization_code = None
        self.access_token = None
        self.refresh_token = None

    def reset_pkce(self) -> None:
        self.PKCE_code_verifier = None
        self.PKCE_code_challenge = None
        self.PKCE_code_challenge_method = None

    def code_request(self, pkce: bool = False) -> dict[str, str]:
        request = {"response_type": "code",
                   "client_id": self.clientId,
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
        sleep(1.)
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

    @tag('client_credentials_flow')
    @task(1)
    class ClientCredentialsFlow(TaskSet):

        def on_start(self):
            self.user.oauth.reset_oauth()

        @tag('correct', '200', 'access_token_client_credentials_flow_200')
        @task(1)
        def access_token_client_credentials_flow_200(self):
            user: OAuthUser = self.user
            with self.client.post(f"{user.token_host}/oauth2/token",
                                  data=user.oauth.token_request('client_credentials'),
                                  auth=(user.oauth.clientId, user.oauth.clientSecret),
                                  verify=False,
                                  allow_redirects=False,
                                  catch_response=True) as r:
                if r.status_code == 200:
                    r.success()
                    r = r.json()
                    access_token = r['access_token']
                    user.oauth.access_token = access_token
                    logging.info(f"{get__name__()} - Got token: {user.oauth!r}")
                else:
                    failstr = f"{get__name__()} - Did not get code 200, code {r.status_code}, error {r.json()}"
                    logging.warning(failstr)
                    r.failure(failstr)
            self.interrupt()

    @tag('authorization_code_flow', 'noPKCE')
    @task(1)
    class AuthorizationCodeFlow(SequentialTaskSet):

        def on_start(self):
            self.user.oauth.reset_oauth()

        @tag('authorization_code')
        @task(1)
        class AuthorizationCode(TaskSet):

            @tag('correct', '302', 'authorization_code_302')
            @task(1)
            def authorization_code_302(self):
                user: OAuthUser = self.user
                with self.client.get(f"{user.code_host}/oauth2/code",
                                     params=user.oauth.code_request(),
                                     auth=('admin', '123456'),
                                     verify=False,
                                     allow_redirects=False,
                                     catch_response=True) as r:
                    if r.status_code == 302:
                        r.success()
                        parsed_redirect = urlparse(r.headers['Location'])
                        redirect_params = parse_qs(parsed_redirect.query)
                        auth_code = redirect_params.get('code')[0]
                        user.oauth.authorization_code = auth_code
                        logging.info(f"{get__name__()} - Got Auth Code: {user.oauth!r}")
                    else:
                        failstr = (f"{get__name__()} - Auth Code: Endpoint did not redirect, code {r.status_code}, "
                                   f"error {r.json()}")
                        logging.warning(failstr)
                        r.failure(failstr)
                        # TODO reschedule to approriate task
                self.interrupt()

        @task(1)
        @tag('access_token')
        class AccessToken(TaskSet):

            @tag('correct', '200', 'access_token_authorization_code_flow_200')
            @task(1)
            def access_token_authorization_code_flow_200(self):
                user: OAuthUser = self.user
                with self.client.post(f"{user.token_host}/oauth2/token",
                                      data=user.oauth.token_request('authorization_code'),
                                      auth=(user.oauth.clientId, user.oauth.clientSecret),
                                      verify=False,
                                      allow_redirects=False,
                                      catch_response = True) as r:
                    if r.status_code == 200:
                        r = r.json()
                        access_token = r['access_token']
                        user.oauth.access_token = access_token
                        logging.info(f"Access Token Authorization Code Flow: {user.oauth!r}")
                    else:
                        logging.warning(f"Access Token Authorization Code Flow: Did not get code 200, error {r.json()}")
                self.interrupt()

    @tag('authorization_code_flow', 'PKCE')
    @task(1)
    class AuthorizationCodeFlowPKCE(SequentialTaskSet):

        def on_start(self):
            self.user.oauth.make_pkce()
            self.user.oauth.reset_oauth()

        @tag('authorization_code')
        @task(1)
        class AuthorizationCodePKCE(TaskSet):

            @tag('correct', '302', 'authorization_code_pkce_302')
            @task(1)
            def authorization_code_pkce_302(self):
                user: OAuthUser = self.user
                with self.client.get(f"{user.code_host}/oauth2/code",
                                     params=user.oauth.code_request(pkce=True),
                                     auth=('admin', '123456'),
                                     verify=False,
                                     allow_redirects=False,
                                     catch_response=True) as r:
                    if r.status_code == 302:
                        r.success()
                        parsed_redirect = urlparse(r.headers['Location'])
                        redirect_params = parse_qs(parsed_redirect.query)
                        auth_code = redirect_params.get('code')[0]
                        user.oauth.authorization_code = auth_code
                        logging.info(f"{get__name__()} - Got Auth Code with PKCE: {user.oauth!r}")
                    else:
                        failstr = (f"{get__name__()} - Auth Code PKCE: Endpoint did not redirect, code {r.status_code}, "
                                    f"error {r.json()}")
                        logging.warning(failstr)
                        r.failure(failstr)
                        # TODO reschedule to appropriate task
                self.interrupt()

        @tag('access_token')
        @task(1)
        class AccessTokenPKCE(TaskSet):

            @tag('correct', '200', 'access_token_authorization_code_flow_pkce_200')
            @task(1)
            def access_token_authorization_code_flow_pkce_200(self):
                user: OAuthUser = self.user
                with self.client.post(f"{user.token_host}/oauth2/token",
                                      data=user.oauth.token_request('authorization_code', pkce=True),
                                      auth=(user.oauth.clientId, user.oauth.clientSecret),
                                      verify=False,
                                      allow_redirects=False,
                                      catch_response=True) as r:
                    if r.status_code == 200:
                        r.success()
                        r = r.json()
                        access_token = r['access_token']
                        user.oauth.access_token = access_token
                        logging.info(f"{get__name__()} - Got token with PKCE: {user.oauth!r}")
                    else:
                        failstr = (f"{get__name__()} - Token endpoint with PKCE: Did not get code 200, "
                                   f"code {r.status_code}, error {r.json()}")
                        logging.warning(failstr)
                        r.failure(failstr)
                self.interrupt()

        def on_stop(self):
            self.user.oauth.reset_pkce()
