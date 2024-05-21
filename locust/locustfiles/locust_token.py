from .mylogging import get__name__

from locust import HttpUser, task, SequentialTaskSet, TaskSet, tag

import logging
import base64
from urllib.parse import urlparse, parse_qs
from hashlib import sha256
from base64 import urlsafe_b64encode
from dataclasses import dataclass, field, InitVar
from os import urandom
from time import sleep

from .locust_client import CLIENTS, Client

__all__ = ['OAuthUser']


@tag('error', '401', 'authorization_code_invalid_password_401')
def authorization_code_invalid_password_401(self):
    user: OAuthUser = self.user
    with self.client.get(f"{user.code_host}/oauth2/code",
                         params=user.oauth.code_request(pkce=True),
                         auth=('admin', 'wrongpassword'),
                         verify=False,
                         allow_redirects=False,
                         catch_response=True) as r:
        if r.status_code == 401:
            r.success()
            failstr = (f"{get__name__()} - Invalid password and response code 401 as expected: "
                       f"error {r}")
            logging.error(failstr)
            r.failure(failstr)
        else:
            failstr = (f"{get__name__()} - Expected 401 for invalid password, got {r.status_code}, "
                       f"error {r.json()}")
            logging.warning(failstr)
            r.failure(failstr)
    self.interrupt()


@tag('error', '400', 'authorization_code_missing_response_type_400')
def authorization_code_missing_response_type_400(self):  # need to add Pkce in this one
    user: OAuthUser = self.user
    invalid_request = user.oauth.code_request(pkce=True)
    del invalid_request['response_type']
    with self.client.get(f"{user.code_host}/oauth2/code",
                         params=invalid_request,
                         auth=('admin', '123456'),
                         verify=False,
                         allow_redirects=False,
                         catch_response=True) as r:
        if r.status_code == 400:
            r.success()
            failstr = (f"{get__name__()} - missing response type and response code 400 as expected:, "
                       f"error {r.json()}")
            logging.error(failstr)
            r.failure(failstr)
        else:
            failstr = (f"{get__name__()} - Expected 400 for invalid response type, got {r.status_code}, "
                       f"error {r.json()}")
            logging.warning(failstr)
            r.failure(failstr)
    self.interrupt()


@tag('error', '400', 'authorization_code_response_not_code_400')
def authorization_code_response_not_code_400(self):
    user: OAuthUser = self.user
    params_with_invalid_response = user.oauth.code_request(pkce=True)
    params_with_invalid_response['response_type'] = 'fail'  # not code
    with self.client.get(f"{user.code_host}/oauth2/code",
                         params=params_with_invalid_response,
                         auth=('admin', '123456'),
                         verify=False,
                         allow_redirects=False,
                         catch_response=True) as r:
        if r.status_code == 400:
            r.success()
            failstr = (f"{get__name__()} - Response type is not code and response code 400 as expected:, "
                       f"error {r.json()}")
            logging.error(failstr)
            r.failure(failstr)
        else:
            failstr = (f"{get__name__()} - Response type noe code : Unexpected status code {r.status_code}, "
                       f"expected 400, received details: {r.json()}")
            logging.warning(failstr)
            r.failure(failstr)
    self.interrupt()


@tag('error', '400', 'authorization_code_client_id_missing_400')
def authorization_code_client_id_missing_400(self):  # need to add Pkce in this one
    user: OAuthUser = self.user
    params = user.oauth.code_request(pkce=True)
    del params['client_id']

    with self.client.get(f"{user.code_host}/oauth2/code",
                         params=params,
                         auth=('admin', '123456'),
                         verify=False,
                         allow_redirects=False,
                         catch_response=True) as r:
        if r.status_code == 400:
            r.success()
            failstr = (f"{get__name__()} - Client ID is missing and response code 400 as expected:, "
                       f"error {r.json()}")
            logging.error(failstr)
            r.failure(failstr)
        else:
            failstr = (f"{get__name__()} - Client ID Missing: Unexpected status code {r.status_code}, "
                       f"expected 400, received details: {r.json()}")
            logging.warning(failstr)
            r.failure(failstr)
    self.interrupt()


@tag('error', '404', 'authorization_code_invalid_client_id_404')
def authorization_code_invalid_client_id_404(self):
    user: OAuthUser = self.user
    params_with_invalid_client = user.oauth.code_request(pkce=True)
    params_with_invalid_client['client_id'] = 'invalid_client_id'
    with self.client.get(f"{user.code_host}/oauth2/code",
                         params=params_with_invalid_client,
                         auth=('admin', '123456'),
                         verify=False,
                         allow_redirects=False,
                         catch_response=True) as r:
        if r.status_code == 404:
            r.success()
            failstr = (f"{get__name__()} - ClientId is not valid and response code 404 as expected:, "
                       f"error {r.json()}")
            logging.error(failstr)
            r.failure(failstr)
        else:
            failstr = (f"{get__name__()} - Client Id not valid : Unexpected status code {r.status_code}, "
                       f"expected 404, received details: {r.json()}")
            logging.warning(failstr)
            r.failure(failstr)
    self.interrupt()


@tag('error', '400', 'access_token_illegal_grant_type_400')
def access_token_invalid_grant_type_400(self):
    user: OAuthUser = self.user
    with self.client.post(f"{user.token_host}/oauth2/token",
                          data=user.oauth.token_request(grant_type='unsupported_grant', pkce=True),
                          auth=(user.oauth.clientId, user.oauth.clientSecret),
                          verify=False,
                          allow_redirects=False,
                          catch_response=True) as r:
        if r.status_code == 400:
            r.success()
            error_response = r.json()
            logging.info(f"{get__name__()} Invalid grant type and response code 400 as expected: {error_response}")
        else:
            failstr = (f"{get__name__()} - Expected 400 for invalid grant type, got {r.status_code}, "
                       f"error {r.json().get('error_description', 'No error description')}")
            logging.warning(failstr)
            r.failure(failstr)
    self.interrupt()


@tag('error', '404', 'access_token_client_id_not_found_404')
def access_token_client_id_not_found_404(self):
    user: OAuthUser = self.user
    with self.client.post(f"{user.token_host}/oauth2/token",
                          data=user.oauth.token_request('authorization_code', pkce=True),
                          auth=("no_id", user.oauth.clientSecret),
                          verify=False,
                          allow_redirects=False,
                          catch_response=True) as r:
        if r.status_code == 404:
            r.success()
            error_response = r.json()
            logging.info(
                f"{get__name__()} - Client ID not found with response code 404 as expected: {error_response['message']}")
        else:
            failstr = (f"{get__name__()} - Expected 404 for client ID not found, got  {r.status_code}, "
                       f"error {r.json().get('message', 'No error description')}")
            logging.warning(failstr)
            r.failure(failstr)
    self.interrupt()


@tag('error', '401', 'access_token_client_secret_wrong_401')
def access_token_client_secret_wrong_401(self):
    user: OAuthUser = self.user
    with self.client.post(f"{user.token_host}/oauth2/token",
                          data=user.oauth.token_request('authorization_code', pkce=True),
                          auth=(user.oauth.clientId, 'invalid'),
                          verify=False,
                          allow_redirects=False,
                          catch_response=True) as r:
        if r.status_code == 401:
            r.success()
            error_response = r.json()
            logging.info(
                f"{get__name__()} - Client secret is wrong with response code 401 as expected: {error_response['message']}")
        else:
            failstr = (f"{get__name__()} - Expected 401 for client secret wrong, got  {r.status_code}, "
                       f"error {r.json().get('message', 'No error description')}")
            logging.warning(failstr)
            r.failure(failstr)
    self.interrupt()


@tag('error', '401', 'access_token_auth_header_error_401')
def access_token_with_incorrect_auth_header_401(self):
    user: OAuthUser = self.user
    with self.client.post(f"{user.token_host}/oauth2/token",
                          data=user.oauth.token_request('authorization_code', pkce=True),
                          headers={"Authorization": "Bearer incorrect_token"},
                          verify=False,
                          allow_redirects=False,
                          catch_response=True) as response:
        if response.status_code == 401:
            response.success()
            error_response = response.json()
            logging.info(f"{get__name__()} - Unauthorized head 401 as expected:{error_response['message']}")
        else:
            failstr = f"{get__name__()} - Expected 401 but got {response.status_code}."
            logging.error(failstr)
            response.failure(failstr)
    self.interrupt()


@tag('error', '400', 'access_token_missing_authorization_header_400')
def access_token_missing_authorization_header_400(self):
    user: OAuthUser = self.user
    with self.client.post(f"{user.token_host}/oauth2/token",
                          data=user.oauth.token_request(grant_type='authorization_code', pkce=True),
                          # Removed the basic auth to simulate missing Authorization header
                          headers={'Authorization': ''},  # TODO not sure how to trigeer the error, get 401 code for this
                          verify=False,
                          allow_redirects=False,
                          catch_response=True) as r:
        if r.status_code == 400:
            r.success()
            error_response = r.json()
            logging.info(
                f"{get__name__()} Missing Authorization header and response code 400 as expected: {error_response}")
        else:
            failstr = (f"{get__name__()} - Expected 400 for missing Authorization header, got {r.status_code}, "
                       f"error {r.json().get('error_description', 'No error description')}")
            logging.warning(failstr)
            r.failure(failstr)
    self.interrupt()


@tag('error', '400', 'access_token_form_urlencoded_400')
def access_token_form_urlencoded_400(self):
    user: OAuthUser = self.user
    with self.client.post(f"{user.token_host}/oauth2/token",
                          headers={"Content-Type": "text/plain"},
                          data=user.oauth.token_request("invalid_data_structure", pkce=True),
                          verify=False,
                          allow_redirects=False,
                          catch_response=True) as response:
        if response.status_code == 400:
            response.success()
            error_response = response.json()
            logging.info(
                f"{get__name__()} - Unable to parse x-www-form-urlencoded status 400 as expected:{error_response['message']}")
        else:
            failstr = f"{get__name__()} - Expected 400 but got {response.status_code}."
            logging.error(failstr)
            response.failure(failstr)
    self.interrupt()


@tag('error', '401', 'access_token_authorization_form_401')
def access_token_authorization_form_401(self):
    user: OAuthUser = self.user
    with self.client.post(f"{user.token_host}/oauth2/token",
                          data=user.oauth.token_request('authorization_code', pkce=True),
                          headers={'Authorization': 'Basic äääää'},
                          verify=False,
                          allow_redirects=False,
                          catch_response=True) as r:
        if r.status_code == 401:
            r.success()
            error_response = r.json()
            logging.info(f"{get__name__()} - Could not decode auth form 401 as expected: {error_response['message']}")
        else:
            failstr = (f"{get__name__()} - Expected 401, got  {r.status_code}, "
                       f"error {r.json().get('message', 'No error description')}")
            logging.warning(failstr)
            r.failure(failstr)
    self.interrupt()


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

            tasks = {authorization_code_invalid_password_401: 1, authorization_code_missing_response_type_400: 1,
                     authorization_code_response_not_code_400: 1, authorization_code_client_id_missing_400: 1,
                     authorization_code_invalid_client_id_404: 1}

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

            tasks = {access_token_invalid_grant_type_400: 1, access_token_client_id_not_found_404: 1,
                     access_token_client_secret_wrong_401: 1, access_token_with_incorrect_auth_header_401: 1,
                     access_token_missing_authorization_header_400: 1, access_token_form_urlencoded_400: 1,
                     access_token_authorization_form_401: 1}

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

            tasks = {authorization_code_invalid_password_401: 1, authorization_code_missing_response_type_400: 1,
                     authorization_code_response_not_code_400: 1, authorization_code_client_id_missing_400: 1,
                     authorization_code_invalid_client_id_404: 1}

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

            # PKCE-specific errors

            @tag('error', '400', 'invalid_code_challenge_method_pkce_400')
            @task(1)
            def invalid_code_challenge_method_pkce_400(self):
                user: OAuthUser = self.user
                invalid_request = user.oauth.code_request(pkce=True)
                invalid_request['code_challenge_method'] = 'invalid'
                with self.client.get(f"{user.code_host}/oauth2/code",
                                     params=invalid_request,
                                     auth=('admin', '123456'),
                                     verify=False,
                                     allow_redirects=False,
                                     catch_response=True) as r:
                    if r.status_code == 400:
                        r.success()
                        failstr = (f"{get__name__()} - Invalid Code Challenge Method and response code 400 as expected:, "
                           f"error {r.json()}")
                        logging.error(failstr)
                        r.failure(failstr)
                    else:
                        failstr = (f"{get__name__()} - Invalid Code Challenge Method expected 400 but got {r.status_code}, "
                           f"expected 400, received details: {r.json()}")
                        logging.warning(failstr)
                        r.failure(failstr)
                self.interrupt()

            @tag('error', '400', 'code_challenge_too_short_pkce_400')
            @task(1)
            def code_challenge_too_short_pkce_400(self):
                user: OAuthUser = self.user
                invalid_request = user.oauth.code_request(pkce=True)
                invalid_request['code_challenge'] = invalid_request['code_challenge'][:20] # Min length is 43, this is 20

                with self.client.get(f"{user.code_host}/oauth2/code",
                                     params=invalid_request,
                                     auth=('admin', '123456'),
                                     verify=False,
                                     allow_redirects=False,
                                     catch_response=True) as r:
                        if r.status_code == 400:
                            r.success()
                            failstr = (f"{get__name__()} - Code Challenge Too Short and response code 400 as expected:, "
                                       f"error {r.json()}")
                            logging.error(failstr)
                            r.failure(failstr)
                        else:
                            # TODO This error is not handled correct, we end up here with response 302
                           failstr = (f"{get__name__()} - Code challenge too short expected 400 but got {r.status_code}, "
                           f"expected 400, received details: {r}")
                           logging.warning(failstr)
                           r.failure(failstr)
                self.interrupt()

            @tag('error', '400', 'code_challenge_too_long_pkce_400')
            @task(1)
            def code_challenge_too_long_pkce_400(self):
                user: OAuthUser = self.user
                invalid_request = user.oauth.code_request(pkce=True)
                invalid_request['code_challenge'] = 'B'*150  # intentionally too long because max size is 128 characters

                with self.client.get(f"{user.code_host}/oauth2/code",
                             params=invalid_request,
                             auth=('admin', '123456'),
                             verify=False,
                             allow_redirects=False,
                             catch_response=True) as r:
                        if r.status_code == 400:
                            r.success()
                            failstr = (f"{get__name__()} - Code Challenge Too long and response code 400 as expected:, "
                                       f"error {r.json()}")
                            logging.error(failstr)
                            r.failure(failstr)
                        else:
                           failstr = (f"{get__name__()} - Code challenge too long expected 400 but got {r.status_code}, "
                           f"expected 400, received details: {r.json()}")
                           logging.warning(failstr)
                           r.failure(failstr)
                self.interrupt()

            @tag('error', '400', 'code_challenge_invalid_format_pkce_400')
            @task(1)
            def code_challenge_invalid_format_pkce_400(self):
                user: OAuthUser = self.user
                invalid_request = user.oauth.code_request(pkce=True)
                invalid_request['code_challenge'] = 'Ä'*50  # Ä is not an allowed character

                with self.client.get(f"{user.code_host}/oauth2/code",
                                     params=invalid_request,
                                     auth=('admin', '123456'),
                                     verify=False,
                                     allow_redirects=False,
                                     catch_response=True) as r:
                        if r.status_code == 400:
                            r.success()
                            failstr = (f"{get__name__()} - Invalid format challenge and response code 400 as expected:, "
                                       f"error {r.json()}")
                            logging.error(failstr)
                            r.failure(failstr)
                        else:
                           failstr = (f"{get__name__()} - Invalid format and expected 400 but got {r.status_code}, "
                           f"expected 400, received details: {r.json()}")
                           logging.warning(failstr)
                           r.failure(failstr)
                self.interrupt()

        @tag('access_token')
        @task(1)
        class AccessTokenPKCE(TaskSet):

            tasks = {access_token_invalid_grant_type_400: 1, access_token_client_id_not_found_404: 1,
                     access_token_client_secret_wrong_401: 1, access_token_with_incorrect_auth_header_401: 1,
                     access_token_missing_authorization_header_400: 1, access_token_form_urlencoded_400: 1,
                     access_token_authorization_form_401: 1}

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
                        print(r)
                        logging.info(f"{get__name__()} - Got token with PKCE: {user.oauth!r}")
                    else:
                        failstr = (f"{get__name__()} - Token endpoint with PKCE: Did not get code 200, "
                                   f"code {r.status_code}, error {r.json()}")
                        logging.warning(failstr)
                        r.failure(failstr)
                self.interrupt()
                
            # PKCE-specific errors

            @tag('error', '400', 'invalid_code_verifier_format_PKCE_400')
            @task(1)
            def invalid_code_verifier_format_pkce_400(self):
                user: OAuthUser = self.user
                invalid_request = user.oauth.token_request(grant_type='authorization_code', pkce=True)
                invalid_request['code_verifier'] = 'Ä' * 100  # Ä is not allowed
                with self.client.post(f"{user.token_host}/oauth2/token",
                                      data=invalid_request,
                                      auth=(user.oauth.clientId, user.oauth.clientSecret),
                                      verify=False,
                                      catch_response=True) as response:
                    if response.status_code == 400:
                            # TODO getting code_verifier_too_long here
                            response.success()
                            error_response = response.json()
                            logging.info(f"{get__name__()} - Invalid code verifier and status 400 as expected:{error_response['message']}")
                    else:
                        failstr = f"{get__name__()} - Expected 400 but got {response.status_code}."
                        logging.error(failstr)
                        response.failure(failstr)
                self.interrupt()

            @tag('error', '400', 'code_verifier_too_short_pkce_400')
            @task(1)
            def code_verifier_too_short_pkce_400(self):
                user: OAuthUser = self.user
                invalid_request = user.oauth.token_request(grant_type='authorization_code', pkce=True)
                invalid_request['code_verifier'] = invalid_request['code_verifier'][:40]  # Min is 43, here is 40

                with self.client.post(f"{user.token_host}/oauth2/token",
                                      data=invalid_request,
                                      auth=(user.oauth.clientId, user.oauth.clientSecret),
                                      verify=False,
                                      catch_response=True) as response:
                    if response.status_code == 400:
                            response.success()
                            error_response = response.json()
                            logging.info(f"{get__name__()} - code verifier too short and status 400 as expected:{error_response['message']}")
                    else:
                        failstr = f"{get__name__()} - Expected 400 but got {response.status_code}."
                        logging.error(failstr)
                        response.failure(failstr)
                self.interrupt()

            @tag('error', '400', 'code_verifier_too_long_pkce_400')
            @task(1)
            def code_verifier_too_long_pkce_400(self):
                user: OAuthUser = self.user
                invalid_request = user.oauth.token_request(grant_type='authorization_code', pkce=True)
                invalid_request['code_verifier'] = 'a' * 150  # Max is 128, here 150

                with self.client.post(f"{user.token_host}/oauth2/token",
                                      data=invalid_request,
                                      auth=(user.oauth.clientId, user.oauth.clientSecret),
                                      verify=False,
                                      catch_response=True) as response:
                    if response.status_code == 400:
                            response.success()
                            error_response = response.json()
                            logging.info(f"{get__name__()} - code verifier too long and status 400 as expected:{error_response['message']}")
                    else:
                        failstr = f"{get__name__()} - Expected 400 but got {response.status_code}."
                        logging.error(failstr)
                        response.failure(failstr)
                self.interrupt()

            @tag('error', '400', 'code_verifier_missing_pkce_400')
            @task(1)
            def code_verifier_missing_pkce_400(self):
                user: OAuthUser = self.user
                invalid_request = user.oauth.token_request(grant_type='authorization_code', pkce=True)
                del invalid_request['code_verifier']

                with self.client.post(f"{user.token_host}/oauth2/token",
                                      data=invalid_request,
                                      auth=(user.oauth.clientId, user.oauth.clientSecret),
                                      verify=False,
                                      catch_response=True) as response:
                    if response.status_code == 400:
                        response.success()
                        error_response = response.json()
                        logging.info(
                            f"{get__name__()} - code verifier missing and status 400 as expected:{error_response['message']}")
                    else:
                        failstr = f"{get__name__()} - Expected 400 but got {response.status_code}."
                        logging.error(failstr)
                        response.failure(failstr)
                self.interrupt()

            @tag('error', '400', 'verification_failed_pkce_400')
            @task(1)
            def verification_failed_pkce_400(self):
                user: OAuthUser = self.user
                user.oauth.make_pkce()
                invalid_request = user.oauth.token_request(grant_type='authorization_code', pkce=True)

                with self.client.post(f"{user.token_host}/oauth2/token",
                                      data=invalid_request,
                                      auth=(user.oauth.clientId, user.oauth.clientSecret),
                                      verify=False,
                                      catch_response=True) as response:
                    if response.status_code == 400:
                        response.success()
                        error_response = response.json()
                        logging.info(
                            f"{get__name__()} - verification failed and status 400 as expected:{error_response['message']}")
                    else:
                        failstr = f"{get__name__()} - Expected 400 but got {response.status_code}."
                        logging.error(failstr)
                        response.failure(failstr)
                self.interrupt()

        def on_stop(self):
            self.user.oauth.reset_pkce()
