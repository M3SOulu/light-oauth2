from .myset import set_with_choice
from .mylogging import get__name__

from locust import HttpUser, task, TaskSet, tag

import logging
from uuid import uuid4
from dataclasses import dataclass, field, replace

# Documentation: https://doc.networknt.com/service/oauth/service/client/

__all__ = ['CLIENTS', 'Client', 'ClientRegistration']

CLIENTS = set_with_choice()


@dataclass(init=True, repr=True, eq=False)
class Client:
    clientId: str = field(repr=True, hash=True)
    clientSecret: str = field(repr=False, hash=False)
    clientName: str = field(default_factory=lambda: str(uuid4())[:32], repr=False, hash=False)
    clientDesc: str = field(default_factory=lambda: str(uuid4()), repr=False, hash=False)
    clientProfile: str = field(default="mobile", repr=True, hash=False) # TODO put different if important?
    clientType: str = field(default="public", repr=True, hash=False) # TODO implement different types for different auth flows
    scope: str = field(default="read write", repr=True, hash=False) # TODO implement different scopes
    ownerId: str = field(default="admin", repr=True, hash=False) # TODO implement different users
    host: str = field(default="lightapi.net", repr=False, hash=False)
    redirectUri: str = field(default="http://localhost:8000/authorization", repr=False, hash=False)
    endpoints: list[str] = field(default_factory=list, repr=False, hash=False)

    def to_dict(self):
        return {"clientType": self.clientType,
                "clientProfile": self.clientProfile,
                "clientName": self.clientName,
                "clientDesc": self.clientDesc,
                "scope": self.scope,
                "redirectUri": self.redirectUri,
                "ownerId": self.ownerId,
                "host": self.host}


class ClientRegistration(HttpUser):

    fixed_count = 1
    host = "https://localhost:6884"

    def on_start(self):
        c = Client(clientId="none", clientSecret="none")
        with self.client.post("/oauth2/client", data=c.to_dict(),
                              verify=False, allow_redirects=False,
                              catch_response=True) as r:
            if r.status_code == 200:
                t = r.json()
                c.clientId = t['clientId']
                c.clientSecret = t['clientSecret']
                logging.info(f"Registered client: {c!r}")
                CLIENTS.add(c)
                r.success()
            else:
                raise RuntimeError(f"First attempt to register Client failed, status code was {r.status_code}")

    @task(1)
    class RegisterClient(TaskSet):

        @task(1)
        @tag('correct', 'register', '200', 'register_client_200')
        def register_client_200(self):
            c = Client(clientId="none", clientSecret="none")
            with self.client.post("/oauth2/client", data=c.to_dict(),
                                  verify=False,
                                  allow_redirects=False,
                                  catch_response=True) as r:
                if r.status_code == 200:
                    t = r.json()
                    c.clientId = t['clientId']
                    c.clientSecret = t['clientSecret']
                    CLIENTS.add(c)
                    logging.info(f"{get__name__()} - Registered client: {c!r}")
                    r.success()
                else:
                    del c
                    failure_str = (f"{get__name__()} - Client registration did not return code 200, code {r.status_code}, "
                                   f"error {r.json()}")
                    logging.warning(failure_str)
                    r.failure(failure_str)
            self.interrupt()

        @task(1)
        @tag('error', 'register', '400', 'register_client_400_clientType')
        def register_client_400_clientType(self):
            try:
                c = CLIENTS.choice()
            except KeyError:
                self.interrupt()
            c2 = replace(c, clientType="none")
            with self.client.post("/oauth2/client", data=c2.to_dict(),
                                  verify=False,
                                  allow_redirects=False,
                                  catch_response=True) as r:

                if r.status_code == 400:
                    logging.error(f"{get__name__()} - Client Registration: error code 400 returned as expected")
                    r.success()
                else:
                    failure_str = (f"{get__name__()} - Client Registration: did not return code 400, code {r.status_code}, "
                                   f"error {r.json()}")
                    logging.warning(failure_str)
                    r.failure(failure_str)
            del c2
            self.interrupt()

        @task(1)
        @tag('error', 'register', '400', 'register_client_400_clientProfile')
        def register_client_400_clientProfile(self):
            try:
                c = CLIENTS.choice()
            except KeyError:
                self.interrupt()
            c2 = replace(c, clientProfile="none")
            with self.client.post("/oauth2/client", data=c2.to_dict(),
                                  verify=False,
                                  allow_redirects=False,
                                  catch_response=True) as r:

                if r.status_code == 400:
                    logging.error(f"{get__name__()} - Client Registration: error code 400 returned as expected")
                    r.success()
                else:
                    failure_str = (f"{get__name__()} - Client Registration: did not return code 400, code {r.status_code}, "
                                   f"error {r.json()}")
                    logging.warning(failure_str)
                    r.failure(failure_str)
            del c2
            self.interrupt()

        @task(1)
        @tag('error', 'register', '404', 'register_client_404_no_user')
        def register_client_404_no_user(self):
            try:
                c = CLIENTS.choice()
            except KeyError:
                self.interrupt()
            c2 = replace(c, ownerId="nouser")
            with self.client.post("/oauth2/client", data=c2.to_dict(),
                                  verify=False,
                                  allow_redirects=False,
                                  catch_response=True) as r:
                if r.status_code == 404:
                    logging.error(f"{get__name__()} - Registration: error code 404 returned as expected")
                    r.success()
                else:
                    failure_str = (f"{get__name__()} - Client Registration: did not return code 404, code {r.status_code}, "
                                   f"error {r.json()}")
                    logging.warning(failure_str)
                    r.failure(failure_str)
            del c2
            self.interrupt()

    @task(1)
    class UpdateClient(TaskSet):

        @task(1)
        @tag('correct', 'update', '200', 'update_client_200')
        def update_client_200(self):
            try:
                c = CLIENTS.pop()
            except KeyError:
                self.interrupt()
            c2 = replace(c, clientName=str(uuid4())[:32])

            with self.client.put("/oauth2/client", json=c2.to_dict(),
                                 verify=False,
                                 allow_redirects=False,
                                 catch_response=True) as r:
                if r.status_code == 200:
                    CLIENTS.add(c2)
                    del c
                    logging.info(f"{get__name__()} - Updated client: {c2!r}")
                    r.success()
                else:
                    CLIENTS.add(c)
                    del c2
                    failure_str = (f"{get__name__()} - Client update failed with unexpected status code: {r.status_code}, "
                                   f"error {r.json()}")
                    logging.warning(failure_str)
                    r.failure(failure_str)
            self.interrupt()

        @task(1)
        @tag('error', 'update', '400', 'update_client_400_clientType')
        def update_client_400_clientType(self):
            try:
                c = CLIENTS.pop()
                CLIENTS.add(c)
            except KeyError:
                self.interrupt()
            c2 = replace(c, clientType="none")
            with self.client.put("/oauth2/client", json=c2.to_dict(),
                                 verify=False,
                                 allow_redirects=False,
                                 catch_response=True) as r:
                if r.status_code == 400:
                    logging.error(f"{get__name__()} - Client update with wrong clientType failed as expected, 400")
                    r.success()
                else:
                    if r.status_code == 200:
                        CLIENTS.discard(c)
                    failstr = (f"{get__name__()} - Unexpected status code when updating client with wrong clientType, "
                               f"code {r.status_code}, error {r.json()}")
                    logging.warning(failstr)
                    r.failure(failstr)
            del c2
            self.interrupt()

        @task(1)
        @tag('error', 'update', '400', 'update_client_400_clientProfile')
        def update_client_400_clientProfile(self):
            try:
                c = CLIENTS.pop()
                CLIENTS.add(c)
            except KeyError:
                self.interrupt()
            c2 = replace(c, clientProfile="none")
            with self.client.put("/oauth2/client", json=c2.to_dict(),
                                 verify=False,
                                 allow_redirects=False,
                                 catch_response=True) as r:
                if r.status_code == 400:
                    logging.error(f"{get__name__()} - Client update with wrong clientProfile failed as expected, 400")
                    r.success()
                else:
                    if r.status_code == 200:
                        CLIENTS.discard(c)
                    failstr = (f"{get__name__()} - Unexpected status code when updating client with wrong clientProfile, "
                               f"code {r.status_code}, error {r.json()}")
                    logging.warning(failstr)
                    r.failure(failstr)
            del c2
            self.interrupt()

        @task(1)
        @tag('error', 'update', '404', 'update_client_404_ownerId')
        def update_client_404_ownerId(self):
            try:
                c = CLIENTS.pop()
                CLIENTS.add(c)
            except KeyError:
                self.interrupt()
            c2 = replace(c, ownerId="nouser")
            with self.client.put("/oauth2/client", json=c2.to_dict(),
                                 verify=False,
                                 allow_redirects=False,
                                 catch_response=True) as r:
                if r.status_code == 404:
                    logging.error(f"{get__name__()} - Client update with wrong ownerId failed as expected, 400")
                    r.success()
                else:
                    if r.status_code == 200:
                        CLIENTS.discard(c)
                    failstr = (f"{get__name__()} - Unexpected status code when updating client with wrong ownerId, "
                               f"code {r.status_code}, error {r.json()}")
                    logging.warning(failstr)
                    r.failure(failstr)
            del c2
            self.interrupt()

        @task(1)
        @tag('error', 'update', '404', 'update_client_404_clientId')
        def update_client_404_clientId(self):
            try:
                c = CLIENTS.choice()
            except KeyError:
                self.interrupt()
            c2 = replace(c, clientId="", clientName=str(uuid4())[:32])

            with self.client.put("/oauth2/client", json=c2.to_dict(),
                                 verify=False,
                                 allow_redirects=False,
                                 catch_response=True) as r:
                if r.status_code == 404:
                    logging.error(f"{get__name__()} - Client update without id failed as expected, 404")
                    r.success()
                else:
                    failstr = (f"{get__name__()} - Unexpected status code when updating client without id, "
                               f"code {r.status_code}, error {r.json()}")
                    logging.warning(failstr)
                    r.failure(failstr)
            del c2
            self.interrupt()

    @task(1)
    class DeleteClient(TaskSet):
        # @task(1)
        # @tag('correct', 'delete', '200', 'delete_client_200')
        # def delete_client_200(self):
        #     try:
        #         c = CLIENTS.pop()
        #     except KeyError:
        #         self.interrupt()
        #     with self.client.delete(f"/oauth2/client/{c.clientId}",
        #                             verify=False,
        #                             allow_redirects=False,
        #                             catch_response=True) as r:
        #         if r.status_code == 200:
        #             logging.info(f"{get__name__()} - Deleted client: {c!r}")
        #             r.success()
        #         else:
        #             CLIENTS.add(c)
        #             failure_str = (f'{get__name__()} - Client deletion did not return code 200, code {r.status_code}, '
        #                            f'error {r.json()}')
        #             logging.warning(failure_str)
        #             r.failure(failure_str)
        #     del c
        #     self.interrupt()

        @task(1)
        @tag('error', 'delete', '404', 'delete_client_404_no_client')
        def delete_client_404_no_client(self):
            with self.client.delete(f"/oauth2/client/not_a_client_id",
                                    verify=False,
                                    allow_redirects=False,
                                    catch_response=True) as r:
                if r.status_code == 404:
                    logging.error(f"{get__name__()} - Client deletion: error code 404 returned as expected")
                    r.success()
                else:
                    failure_str = (f"{get__name__()} - Client deletion: did not return code 404, code {r.status_code}, "
                                   f"error {r.json()}")
                    logging.warning(failure_str)
                    r.failure(failure_str)
            self.interrupt()

    @task(1)
    class GetClient(TaskSet):
        @task(1)
        @tag('correct', 'get', '200', 'get_client_200')
        def get_client_200(self):
            try:
                c = CLIENTS.choice()
            except KeyError:
                self.interrupt()
            with self.client.get(f"/oauth2/client/{c.clientId}",
                                 verify=False,
                                 allow_redirects=False,
                                 catch_response=True) as r:
                if r.status_code == 200:
                    logging.info(f"{get__name__()} - Got client: {c!r}")
                    r.success()
                else:
                    failure_str = (f'{get__name__()}- Client get did not return code 200, code {r.status_code}, '
                                   f'error {r.json()}')
                    logging.warning(failure_str)
                    r.failure(failure_str)
            self.interrupt()

        @task(1)
        @tag('error', 'get', '404', 'get_client_404_no_client')
        def get_client_404_no_client(self):
            with self.client.get(f"/oauth2/client/none",
                                 verify=False,
                                 allow_redirects=False,
                                 catch_response=True) as r:
                if r.status_code == 404:
                    logging.error(f"{get__name__()} - Tried to get client with bad id, status 404 as expected.")
                    r.success()
                else:
                    failure_str = (f'{get__name__()} - Get client with bad id got unexpected status code {r.status_code}, '
                                   f'error {r.json()}')
                    logging.warning(failure_str)
                    r.failure(failure_str)
            self.interrupt()

    @task(1)
    class GetClientPage(TaskSet):
        @task(1)
        @tag('correct', 'get', '200', 'get_client_page_200')
        def get_client_page_200(self):
            with self.client.get(f"/oauth2/client", params={'page': '1'},
                                 verify=False,
                                 allow_redirects=False,
                                 catch_response=True) as r:
                if r.status_code == 200:
                    logging.info(f"{get__name__()} - Got client page with status_code 200")
                    r.success()
                else:
                    failure_str = (f'{get__name__()} - Client page get did not return code 200, code {r.status_code}, '
                                   f'error {r.json()}')
                    logging.warning(failure_str)
                    r.failure(failure_str)
            self.interrupt()

        @task(1)
        @tag('error', 'get', '400', 'get_client_page_400_no_page')
        def get_client_page_400_no_page(self):
            with self.client.get("/oauth2/client", params={},
                                 verify=False,
                                 allow_redirects=False,
                                 catch_response=True) as r:
                if r.status_code == 400:
                    logging.error(f"{get__name__()} - Called client page without page, status 400 as expected.")
                    r.success()
                else:
                    failure_str = (f"{get__name__()} - Client page get did not return code 400, code {r.status_code}, "
                                   f"error {r.json()}")
                    logging.warning(failure_str)
                    r.failure(failure_str)
            self.interrupt()
