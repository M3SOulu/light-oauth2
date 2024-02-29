from locust import HttpUser, task, TaskSet, tag
from locust.exception import RescheduleTask

import logging
from collections import namedtuple
from uuid import uuid4

# Documentation: https://doc.networknt.com/service/oauth/service/client/

__all__ = ['CLIENTS', 'Client', 'ClientRegistration']

CLIENTS = set()
Client = namedtuple("Client", ["clientName", "clientId", "clientSecret"])


class ClientRegistration(HttpUser):

    fixed_count = 1
    host = "https://localhost:6884"

    @task(1)
    class RegisterClient(TaskSet):

        @task(1)
        @tag('correct', 'register', '200')
        def register_client_200(self):
            with self.client.post("/oauth2/client", data=
            {
                "clientType": "public",  # TODO implement different types for different auth flows
                "clientProfile": "mobile",  # TODO put different if important?
                "clientName": str(uuid4())[:32],
                "clientDesc": str(uuid4()),
                "scope": "read write",  # TODO implement different scopes
                "redirectUri": "http://localhost:8000/authorization",
                "ownerId": "admin",  # TODO implement different users
                "host": "lightapi.net"
            }, verify=False, allow_redirects=False, catch_response=True) as r:

                if r.status_code == 200:
                    t = r.json()
                    logging.info(f"Registered client: clientName = {t['clientName']}, clientId = {t['clientId']},"
                                 f" clientSecret = {t['clientSecret']}")
                    CLIENTS.add(Client(t['clientName'], t['clientId'], t['clientSecret']))
                    r.success()
                else:
                    logging.info("Client registration did not return code 200")
                    r.failure("Client registration did not return code 200")
                self.interrupt()

        @task(1)
        @tag('error', 'register', '400')
        def register_client_400_clientType(self):
            with self.client.post("/oauth2/client", data=
            {
                "clientType": "none",  # Error here
                "clientProfile": "mobile",
                "clientName": str(uuid4())[:32],
                "clientDesc": str(uuid4()),
                "scope": "read write",
                "redirectUri": "http://localhost:8000/authorization",
                "ownerId": "admin",
                "host": "lightapi.net"
            }, verify=False, allow_redirects=False, catch_response=True) as r:

                if r.status_code == 400:
                    logging.info(f"Client Registration: error code 400 returned as expected (wrong clientType)")
                    r.success()
                else:
                    failure_str = "Client Registration: did not return code 400 (clientType). Instead: " + str(r.status_code)
                    logging.info(failure_str)
                    r.failure(failure_str)
                self.interrupt()

        @task(1)
        @tag('error', 'register', '400')
        def register_client_400_clientProfile(self):
            with self.client.post("/oauth2/client", data=
            {
                "clientType": "public",
                "clientProfile": "none",
                "clientName": str(uuid4())[:32],
                "clientDesc": str(uuid4()),
                "scope": "read write",
                "redirectUri": "http://localhost:8000/authorization",
                "ownerId": "admin",
                "host": "lightapi.net"
            }, verify=False, allow_redirects=False, catch_response=True) as r:

                if r.status_code == 400:
                    logging.info(f"Client Registration: error code 400 returned as expected (wrong clientProfile)")
                    r.success()
                else:
                    failure_str = "Client Registration: did not return code 400 (clientProfile). Instead: " + str(r.status_code)
                    logging.info(failure_str)
                    r.failure(failure_str)
                self.interrupt()

        @task(1)
        @tag('error', 'register', '404')
        def register_client_404(self):
            with self.client.post("/oauth2/client", data=
            {
                "clientType": "public",
                "clientProfile": "mobile",
                "clientName": str(uuid4())[:32],
                "clientDesc": str(uuid4()),
                "scope": "read write",
                "redirectUri": "http://localhost:8000/authorization",
                "ownerId": "nouser",  # Error here
                "host": "lightapi.net"
            }, verify=False, allow_redirects=False, catch_response=True) as r:
                if r.status_code == 404:
                    logging.info("Client Registration: error code 404 returned as expected (non-existent user)")
                    r.success()
                else:
                    failure_str = "Client Registration: did not return code 404. Instead: " + str(r.status_code)
                    logging.info(failure_str)
                    r.failure(failure_str)
                self.interrupt()

### Update client start
    @task(1)
    @tag('correct', 'update', '200')
    def update_client_200(self):
        try:
            c = CLIENTS.pop()
        except KeyError:
            #logging.info("No clients available to update")
            raise RescheduleTask()

        updated_data = {
            "clientId": c.clientId,
            "clientType": "public",  # Assuming 'public' is a valid clientType
            "clientProfile": "mobile",
            "clientName": str(uuid4())[:32],
            "clientDesc": str(uuid4()),
            "scope": "read write",
            "redirectUri": "http://localhost:8000/authorization",
            "ownerId": "admin",  # Assuming 'admin' is a valid ownerId
            "host": "lightapi.net"
        }

        with self.client.put("/oauth2/client", json=updated_data, verify=False, allow_redirects=False, catch_response=True) as r:
            if r.status_code == 200:
                logging.info(f"Updated client: clientId = {updated_data['clientId']}")
                CLIENTS.add(Client(updated_data['clientName'], c.clientId, c.clientSecret)) #for the stored client tuple, only name changes
                r.success()
            else:
                CLIENTS.add(c)
                logging.info(f"Client update failed with unexpected status code: {r.status_code}")
                r.failure(f"Client update failed with unexpected status code: {r.status_code}")


    @task(1)
    @tag('error', 'update', '404')
    def update_client_404(self):
        try:
            c = CLIENTS.pop()
        except KeyError:
            #logging.info("No clients available to update")
            raise RescheduleTask()

        updated_data = {
            "clientId": "",
            "clientType": "public",  # Assuming 'public' is a valid clientType
            "clientProfile": "mobile",
            "clientName": str(uuid4())[:32],
            "clientDesc": str(uuid4()),
            "scope": "read write",
            "redirectUri": "http://localhost:8000/authorization",
            "ownerId": "admin",  # Assuming 'admin' is a valid ownerId
            "host": "lightapi.net"
        }

        with self.client.put("/oauth2/client", json=updated_data, verify=False, allow_redirects=False, catch_response=True) as r:
            if r.status_code == 404:
                logging.info(f"Client update without id failed as expected, 404")
                CLIENTS.add(c)
                r.success()
            else:
                CLIENTS.add(c)
                failstr = str(f"Unexpected status code when updating client without id: {r.status_code}")
                logging.info(failstr)
                r.failure(failstr)
### Update client end

    @task(1)
    class DeleteClient(TaskSet):
        @task(1)
        @tag('correct', 'delete', '200')
        def delete_client_200(self):
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
            self.interrupt()

        @task(1)
        @tag('error', 'delete', '404')
        def delete_client_404(self):
            with self.client.delete(f"/oauth2/client/not_a_client_id", verify=False, allow_redirects=False, catch_response=True) as r:
                if r.status_code == 404:
                    logging.info("Client deletion: error code 404 returned as expected (non-existent user)")
                    r.success()
                else:
                    failure_str = "Client deletion: did not return code 404. Instead: " + str(r.status_code)
                    logging.info(failure_str)
                    r.failure(failure_str)
            self.interrupt()

    @task(1)
    class GetClient(TaskSet):
        @task(1)
        @tag('correct', 'get', '200')
        def get_client_200(self):
            try:
                c = CLIENTS.pop()
            except KeyError:
                raise RescheduleTask()
            r = self.client.get(f"/oauth2/client/{c.clientId}", verify=False, allow_redirects=False)
            if r.status_code == 200:
                logging.info(f"Got client: clientName = {c.clientName}, clientId = {c.clientId},"
                             f" clientSecret = {c.clientSecret}")
            else:
                logging.info(f'Client get did not return code 200. Instead: {r.status_code}')
            CLIENTS.add(c)
            self.interrupt()

        @task(1)
        @tag('error', 'get', '404')
        def get_client_404(self):
            with self.client.get(f"/oauth2/client/none", verify=False, allow_redirects=False, catch_response=True) as r:
                if r.status_code == 404:
                    logging.info("Tried to get client with bad id, status 404 as expected.")
                    r.success()
                else:
                    failure_str = str(f'Get client with bad id got unexpected status code {r.status_code}')
                    logging.info(failure_str)
                    r.failure(failure_str)
            self.interrupt()

    @task(1)
    class GetClientPage(TaskSet):
        @task(1)
        @tag('correct', 'get', '200')
        def get_client_page_200(self):
            r = self.client.get(f"/oauth2/client", params={'page': '1'}, verify=False, allow_redirects=False)
            if r.status_code == 200:
                logging.info(f"Got client page with status_code 200.")
            else:
                logging.info(f'Client page get did not return code 200. Instead: {r.status_code}')
            self.interrupt()

        @task(1)
        @tag('error', 'get', '400')
        def get_client_page_400(self):
            with self.client.get("/oauth2/client", params={}, verify=False, allow_redirects=False, catch_response=True) as r:
                if r.status_code == 400:
                    logging.info("Called client page without page, status 400 as expected.")
                    r.success()
                else:
                    failure_str = "Client page get did not return code 400. Instead: " + str(r.status_code)
                    logging.info(failure_str)
                    r.failure(failure_str)
            self.interrupt()

    # Basically a template, doesn't work yet
    @task(0)
    @tag('link', 'service')
    def link_service(self):
        clientId = 'test'
        serviceId = 'test'
        endpoints = ['endpoint1', 'endpoint2', 'endpoint3']

        with self.client.post(f"/oauth2/client/{clientId}/service/{serviceId}",
                            json=endpoints,
                            verify=False,
                            allow_redirects=False,
                            catch_response=True) as r:
            if r.status_code == 200:
                logging.info(f"Service link success, 200")
                r.success()
            else:
                failure_str = str(f"Service link failed: {r.text}")
                logging.info(failure_str)
                r.failure(failure_str)

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
