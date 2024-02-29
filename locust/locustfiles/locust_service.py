from locust import HttpUser, TaskSet, task, tag
from locust.exception import RescheduleTask
import logging
from uuid import uuid4
from collections import namedtuple

__all__ = ['SERVICES', 'Service', 'ServiceRegistration']

SERVICES = set()
Service = namedtuple("Service", ["serviceName", "serviceId"])


class ServiceRegistration(HttpUser):

    fixed_count = 1
    host = "https://localhost:6883"

    @task(1)
    class RegisterService(TaskSet):

        @task(1)
        @tag('correct', 'register', '200')
        def register_service_200(self):
            with self.client.post("/oauth2/service", data={
                "serviceType": "openapi",
                "serviceId": str(uuid4())[:8],  
                "serviceName": str(uuid4())[:32],
                "serviceDesc": str(uuid4()),
                "scope": "read write",
                "ownerId": "admin",
                "host": "lightapi.net"
            }, verify=False, allow_redirects=False, catch_response=True) as r:

                if r.status_code == 200:
                    t = r.json()
                    logging.info(f"Registered service: serviceName = {t['serviceName']}, serviceId = {t['serviceId']}")
                    SERVICES.add(Service(t['serviceName'], t['serviceId']))
                    r.success()
                else:
                    logging.info("Service registration did not return code 200")
                    r.failure("Service registration did not return code 200")
                self.interrupt()

        @task(1)
        @tag('error', 'register', '400')
        def register_service_400_service_id(self):
            try:
                c = SERVICES.pop()
            except KeyError:
                self.interrupt()
            with self.client.post("/oauth2/service", data={
                "serviceType": "openapi",
                "serviceId": c.serviceId,
                "serviceName": str(uuid4())[:32],
                "serviceDesc": str(uuid4()),
                "scope": "read write",
                "ownerId": "admin",
                "host": "lightapi.net"
            }, verify=False, allow_redirects=False, catch_response=True) as r:

                if r.status_code == 400:
                    logging.info("Service Registration: error code 400 returned as expected (existing serviceId )")
                    r.success()
                    SERVICES.add(c)
                else:
                    failure_str = f"Service Registration: did not return code 400 (serviceId). Instead: {r.status_code}"
                    logging.info(failure_str)
                    r.failure(failure_str)
                self.interrupt()

        @task(1)
        @tag('error', 'register', '400')
        def register_service_400_service_type(self):
            with self.client.post("/oauth2/service", data={
                "serviceType": "none",  # Error here
                "serviceId": str(uuid4())[:8], 
                "serviceName": str(uuid4())[:32],
                "serviceDesc": str(uuid4()),
                "scope": "read write",
                "ownerId": "admin",
                "host": "lightapi.net"
            }, verify=False, allow_redirects=False, catch_response=True) as r:

                if r.status_code == 400:
                    logging.info(f"Service Registration: error code 400 returned as expected (wrong serviceType)")
                    r.success()
                else:
                    failure_str = f"Service Registration: did not return code 400 (serviceType). Instead: {r.status_code}"
                    logging.info(failure_str)
                    r.failure(failure_str)
                self.interrupt()

        @task(1)
        @tag('error', 'register', '404')
        def register_service_404(self):
            with self.client.post("/oauth2/service", data={
                "serviceType": "openapi",
                "serviceId": str(uuid4())[:8],
                "serviceName": str(uuid4())[:32],
                "serviceDesc": str(uuid4()),
                "scope": "read write",
                "ownerId": "nouser",  # Error here
                "host": "lightapi.net"
            }, verify=False, allow_redirects=False, catch_response=True) as r:
                if r.status_code == 404:
                    logging.info("Service Registration: error code 404 returned as expected (non-existent user)")
                    r.success()
                else:
                    failure_str = f"Service Registration: did not return code 404. Instead: {r.status_code}"
                    logging.info(failure_str)
                    r.failure(failure_str)
                self.interrupt()

    @task(1)
    class UpdateService(TaskSet):

        @task(1)
        @tag('correct', 'update', '200')
        def update_service_200(self):
            try:
                c = SERVICES.pop()
            except KeyError:
                raise RescheduleTask()
            updated_data = {
                "serviceId": c.serviceId,
                "serviceType": "swagger",
                "serviceName": str(uuid4())[:32],
                "serviceDesc": str(uuid4()),
                "scope": "read write",
                "ownerId": "admin",
                "host": "lightapi.net"

            }

            with self.client.put("/oauth2/service", json=updated_data,
                                 verify=False, allow_redirects=False,
                                 catch_response=True) as r:
                if r.status_code == 200:
                    logging.info(f"Updated service: serviceId = {updated_data['serviceId']}")
                    SERVICES.add(Service(updated_data['serviceName'], c.serviceId))
                    r.success()
                else:
                    SERVICES.add(c)
                    logging.info(f"Service update failed with unexpected status code: {r.status_code}")
                    r.failure(f"Service update failed with unexpected status code: {r.status_code}")
                self.interrupt()

        @task(1)
        @tag('error', 'update', '404')
        def update_service_404_user_id(self):
            try:
                c = SERVICES.pop()
            except KeyError:
                raise RescheduleTask()

            updated_data = {
                "serviceId": c.serviceId,
                "serviceType": "swagger",
                "serviceName": str(uuid4())[:32],
                "serviceDesc": str(uuid4()),
                "scope": "read write",
                "ownerId": "nouser",
                "host": "lightapi.net"
            }

            with self.client.put("/oauth2/service", json=updated_data,
                                 verify=False, allow_redirects=False,
                                 catch_response=True) as r:
                if r.status_code == 404:
                    logging.info(f"service update with unknown user id failed as expected, 404")
                    SERVICES.add(c)
                    r.success()
                else:
                    SERVICES.add(c)
                    failstr = f"Unexpected status code when updating service with unknown user id: {r.status_code}"
                    logging.info(failstr)
                    r.failure(failstr)
                self.interrupt()

        @task(1)
        @tag('error', 'update', '404')
        def update_service_404_service_id(self):
            updated_data = {
                "serviceId": "",
                "serviceType": "swagger",
                "serviceName": str(uuid4())[:32],
                "serviceDesc": str(uuid4()),
                "scope": "read write",
                "ownerId": "admin",
                "host": "lightapi.net"
            }
            
            with self.client.put("/oauth2/service", json=updated_data,
                                 verify=False, allow_redirects=False,
                                 catch_response=True) as r:
                if r.status_code == 404:
                    logging.info(f"service update without id failed as expected, 404")
                    r.success()
                else:
                    failstr = f"Unexpected status code when updating service without id: {r.status_code}"
                    logging.info(failstr)
                    r.failure(failstr)
                self.interrupt()

    @task(1)
    class DeleteService(TaskSet):            
        @task(1)
        @tag('correct', 'delete', '200')
        def delete_service_200(self):
            try:
                c = SERVICES.pop()
            except KeyError:
                raise RescheduleTask()
            r = self.client.delete(f"/oauth2/service/{c.serviceId}", verify=False, allow_redirects=False)
            if r.status_code == 200:
                logging.info(f"Deleted service: serviceName = {c.serviceName}, serviceId = {c.serviceId}")
            else:
                logging.info('Service deletion did not return code 200')
                SERVICES.add(c)
            self.interrupt()

        @task(1)
        @tag('error', 'delete', '404')
        def delete_service_404(self):
            with self.client.delete(f"/oauth2/service/not_service_id", verify=False, allow_redirects=False, catch_response=True) as r:
                if r.status_code == 404:
                    logging.info("service deletion: error code 404 returned as expected")
                    r.success()
                else:
                    failure_str = f"Service deletion: did not return code 404. Instead: {r.status_code}"
                    logging.info(failure_str)
                    r.failure(failure_str)
            self.interrupt()
            
    @task(1)
    class GetService(TaskSet):
        @task(1)
        @tag('correct', 'get', '200')
        def get_service_200(self):
            try:
                c = SERVICES.pop()
            except KeyError:
                raise RescheduleTask()
            r = self.client.get(f"/oauth2/service/{c.serviceId}", verify=False, allow_redirects=False)
            if r.status_code == 200:
                logging.info(f"Got service: serviceName = {c.serviceName}, serviceId = {c.serviceId}")
            else:
                logging.info(f'Service get did not return code 200. Instead: {r.status_code}')
            SERVICES.add(c)
            self.interrupt()

        @task(1)
        @tag('error', 'get', '404')
        def get_service_404(self):
            with self.client.get(f"/oauth2/service/none", verify=False,
                                 allow_redirects=False, catch_response=True) as r:
                if r.status_code == 404:
                    logging.info("Tried to get the service with bad id, status 404 as expected.")
                    r.success()
                else:
                    failure_str = f'Get service with bad id got unexpected status code {r.status_code}'
                    logging.info(failure_str)
                    r.failure(failure_str)
            self.interrupt()
            
    @task(1)
    class GetServicePage(TaskSet):
        @task(1)
        @tag('correct', 'get', '200')
        def get_service_page_200(self):
            r = self.client.get(f"/oauth2/service", params={'page': '1'}, verify=False, allow_redirects=False)
            if r.status_code == 200:
                logging.info(f"Got service page with status_code 200.")
            else:
                logging.info(f'Service page get did not return code 200. Instead: {r.status_code}')
            self.interrupt()

        @task(1)
        @tag('error', 'get', '400')
        def get_service_page_400(self):
            with self.client.get("/oauth2/service", params={},
                                 verify=False, allow_redirects=False,
                                 catch_response=True) as r:
                if r.status_code == 400:
                    logging.info("Called service page without page, status 400 as expected.")
                    r.success()
                else:
                    failure_str = f"service page get did not return code 400. Instead: {r.status_code}"
                    logging.info(failure_str)
                    r.failure(failure_str)
            self.interrupt()
