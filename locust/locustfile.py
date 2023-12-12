from locust import HttpUser, task, SequentialTaskSet
from locust.exception import RescheduleTask

import logging
from urllib.parse import urlparse, parse_qs
from uuid import uuid4
from collections import namedtuple

CLIENTS = set()
Client = namedtuple("Client", ["clientName", "clientId", "clientSecret"])


def set_choice(s):
    a = s.pop()
    s.add(a)
    return a


class OAuthClientRegistration(HttpUser):

    fixed_count = 1
    host = "https://localhost:6884"

    @task(1)
    def register_client(self):
        r = self.client.post("/oauth2/client", data=
        {
            "clientType": "public",  # TODO implement different types for different auth flows
            "clientProfile": "mobile",  # TODO put different if important?
            "clientName": str(uuid4())[:32],
            "clientDesc": str(uuid4()),
            "scope": "read write",  # TODO implement different scopes
            "redirectUri": "http://localhost:8000/authorization",
            "ownerId": "admin",  # TODO implement different users
            "host": "lightapi.net"
        }, verify=False, allow_redirects=False)

        if r.status_code == 200:
            r = r.json()
            logging.info(f"Registered client: clientName = {r['clientName']}, clientId = {r['clientId']},"
                         f" clientSecret = {r['clientSecret']}")
            CLIENTS.add(Client(r['clientName'], r['clientId'], r['clientSecret']))
        else:
            logging.info("Client registration did not return code 200")

    @task(0)
    def update_client(self):
        pass

    @task(1)
    def delete_client(self):
        try:
            c = CLIENTS.pop()
        except KeyError:
            raise RescheduleTask()
        r = self.client.delete(f"/oauth2/client/{c.clientId}", verify=False, allow_redirects=False)
        if r.status_code == 200:
            logging.info(f"Deleted client: clientName = {c.clientName}, clientId = {c.clientId},"
                         f" clientSecret = {c.clientSecret}")
        else:
            logging.info('Client deletion did not return code 200')
            CLIENTS.add(c)

    @task(0)
    def get_client(self):
        pass

    @task(0)
    def get_all_clients(self):
        pass

    @task(0)
    def link_service(self):
        pass

    @task(0)
    def delete_service(self):
        pass

    @task(0)
    def delete_all_services(self):
        pass

    @task(0)
    def get_service(self):
        pass

    @task(0)
    def get_all_services(self):
        pass


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
        self.cl = set_choice(CLIENTS)
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

    @task
    class AuthorizationCodeFlow(SequentialTaskSet):

        def on_start(self):
            self.cl = set_choice(CLIENTS)

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
