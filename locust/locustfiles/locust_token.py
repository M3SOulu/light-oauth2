from locust import HttpUser, task, SequentialTaskSet
from locust.exception import RescheduleTask

import logging
from urllib.parse import urlparse, parse_qs

from .locust_client import CLIENTS

__all__ = ['OAuthUser']


class OAuthUser(HttpUser):

    host = "https://localhost:6882"

    def on_start(self):
        self.token_host = "https://localhost:6882"
        self.code_host = "https://localhost:6881"
        self.auth_code = None
        self.access_token = None
        self.cl = None

    @task
    def access_token_client_credentials_flow(self):
        try:
            self.cl = CLIENTS.pop()
        except KeyError:
            raise RescheduleTask()

        r = self.client.post(
            f"{self.token_host}/oauth2/token", data={"grant_type": "client_credentials"},
            auth=(self.cl.clientId, self.cl.clientSecret),
            verify=False,
            allow_redirects=False)
        if r.status_code == 200:
            r = r.json()
            self.access_token = r['access_token']
            logging.info(f"Access Token Client Credentials Flow: ClientId = {self.cl.clientId}, Access Token = {self.access_token}")
        else:
            r = r.json()
            logging.info(f"Access Token Client Credentials Flow: Did not get code 200, code is {r['statusCode']}, "
                         f"error code is {r['code']}")
        CLIENTS.add(self.cl)

    @task
    class AuthorizationCodeFlow(SequentialTaskSet):

        def on_start(self):
            try:
                self.user.cl = CLIENTS.pop()
            except KeyError:
                self.interrupt()

        @task
        def access_code(self):
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
        def access_token_authorization_code_flow(self):
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
