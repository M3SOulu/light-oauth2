from .myset import set_with_choice
from locust import HttpUser, TaskSet, task, tag
import logging
from uuid import uuid4
from dataclasses import dataclass, field, replace

__all__ = ['SERVICES', 'Service', 'ServiceRegistration']

SERVICES = set_with_choice()


@dataclass(init=True, repr=True, eq=False)
class Service:
    serviceId: str = field(default_factory=lambda: str(uuid4())[:8], repr=True, hash=True)
    serviceName: str = field(default_factory=lambda: str(uuid4())[:32], repr=False, hash=False)
    serviceDesc: str = field(default_factory=lambda: str(uuid4()), repr=False, hash=False)
    serviceType: str = field(default="openapi", repr=True, hash=False)
    scope: str = field(default="read write", repr=True, hash=False)
    ownerId: str = field(default="admin", repr=False, hash=False)
    host: str = field(default="lightapi.net", repr=False, hash=False)
    endpoints: list[str] = field(default_factory=list, repr=False, hash=False)

    def to_dict(self):
        return {"serviceType": self.serviceType,
                "serviceId": self.serviceId,
                "serviceName": self.serviceName,
                "serviceDesc": self.serviceDesc,
                "scope": self.scope,
                "ownerId": self.ownerId,
                "host": self.host}


class ServiceRegistration(HttpUser):

    fixed_count = 1
    host = "https://localhost:6883"

    def on_start(self):
        service = Service()
        with self.client.post("/oauth2/service", data=service.to_dict(),
                              verify=False, allow_redirects=False,
                              catch_response=True) as r:

            if r.status_code == 200:
                logging.info(f"Registered service: {service!r}")
                SERVICES.add(service)
                r.success()
            else:
                raise RuntimeError(f"First attempt to register Service failed, return code was {r.status_code}")

    @task(1)
    class RegisterService(TaskSet):

        @task(1)
        @tag('correct', 'register', '200', 'register_service_200')
        def register_service_200(self):
            service = Service()
            with self.client.post("/oauth2/service", data=service.to_dict(),
                                  verify=False,
                                  allow_redirects=False,
                                  catch_response=True) as r:

                if r.status_code == 200:
                    logging.info(f"Registered service: {service!r}")
                    SERVICES.add(service)
                    r.success()
                else:
                    del service
                    logging.warning("Service registration did not return code 200")
                    r.failure("Service registration did not return code 200")
            self.interrupt()

        @task(1)
        @tag('error', 'register', '400', 'register_service_400_service_id')
        def register_service_400_service_id(self):
            try:
                service = SERVICES.choice()
            except KeyError:
                self.interrupt()
            with self.client.post("/oauth2/service", data=service.to_dict(),
                                  verify=False,
                                  allow_redirects=False,
                                  catch_response=True) as r:
                if r.status_code == 400:
                    logging.error("Service Registration: error code 400 returned as expected (existing serviceId )")
                    r.success()
                else:
                    failure_str = f"Service Registration: did not return code 400 (serviceId). Instead: {r.status_code}"
                    logging.warning(failure_str)
                    r.failure(failure_str)
            self.interrupt()

        @task(1)
        @tag('error', 'register', '400', 'register_service_400_service_type')
        def register_service_400_service_type(self):
            service = Service(serviceType="none")
            with self.client.post("/oauth2/service", data=service.to_dict(),
                                  verify=False,
                                  allow_redirects=False,
                                  catch_response=True) as r:

                if r.status_code == 400:
                    logging.error(f"Service Registration: error code 400 returned as expected (wrong serviceType)")
                    r.success()
                else:
                    failure_str = f"Service Registration: did not return code 400 (serviceType). Instead: {r.status_code}"
                    logging.warning(failure_str)
                    r.failure(failure_str)
            self.interrupt()

        @task(1)
        @tag('error', 'register', '404', 'register_service_404_no_user')
        def register_service_404_no_user(self):
            service = Service(ownerId="nouser")
            with self.client.post("/oauth2/service", data=service.to_dict(),
                                  verify=False,
                                  allow_redirects=False,
                                  catch_response=True) as r:
                if r.status_code == 404:
                    logging.error("Service Registration: error code 404 returned as expected (non-existent user)")
                    r.success()
                else:
                    failure_str = f"Service Registration: did not return code 404. Instead: {r.status_code}"
                    logging.warning(failure_str)
                    r.failure(failure_str)
            self.interrupt()

    @task(1)
    class UpdateService(TaskSet):

        @task(1)
        @tag('correct', 'update', '200', 'update_service_200')
        def update_service_200(self):
            try:
                service = SERVICES.pop()
            except KeyError:
                self.interrupt()
            service2 = replace(service, serviceId=service.serviceId, serviceType="swagger")

            with self.client.put("/oauth2/service", json=service2.to_dict(),
                                 verify=False,
                                 allow_redirects=False,
                                 catch_response=True) as r:
                if r.status_code == 200:
                    SERVICES.add(service2)
                    logging.info(f"Updated service: {service2!r}")
                    del service
                    r.success()
                else:
                    SERVICES.add(service)
                    del service2
                    failure_str = f"Service update failed with unexpected status code: {r.status_code}"
                    logging.warning(failure_str)
                    r.failure(failure_str)
            self.interrupt()

        @task(1)
        @tag('error', 'update', '404', 'update_service_404_user_id')
        def update_service_404_user_id(self):
            try:
                service = SERVICES.choice()
            except KeyError:
                self.interrupt()
            service2 = replace(service, serviceId=service.serviceId, serviceType="swagger",
                               ownerId="nouser")

            with self.client.put("/oauth2/service", json=service2.to_dict(),
                                 verify=False,
                                 allow_redirects=False,
                                 catch_response=True) as r:
                if r.status_code == 404:
                    logging.error(f"service update with unknown user id failed as expected, 404")
                    r.success()
                else:
                    failstr = f"Unexpected status code when updating service with unknown user id: {r.status_code}"
                    logging.warning(failstr)
                    r.failure(failstr)
            self.interrupt()

        @task(1)
        @tag('error', 'update', '404', 'update_service_404_service_id')
        def update_service_404_service_id(self):
            try:
                service = SERVICES.choice()
            except KeyError:
                self.interrupt()
            service2 = replace(service, serviceId="")

            with self.client.put("/oauth2/service", json=service2.to_dict(),
                                 verify=False,
                                 allow_redirects=False,
                                 catch_response=True) as r:
                if r.status_code == 404:
                    logging.error(f"service update without id failed as expected, 404")
                    r.success()
                else:
                    failstr = f"Unexpected status code when updating service without id: {r.status_code}"
                    logging.warning(failstr)
                    r.failure(failstr)
            self.interrupt()

    @task(1)
    class DeleteService(TaskSet):            
        @task(1)
        @tag('correct', 'delete', '200', 'delete_service_200')
        def delete_service_200(self):
            try:
                service = SERVICES.pop()
            except KeyError:
                self.interrupt()
            with self.client.delete(f"/oauth2/service/{service.serviceId}",
                                    verify=False,
                                    allow_redirects=False,
                                    catch_response=True) as r:
                if r.status_code == 200:
                    del service
                    logging.info(f"Deleted service: {service!r}")
                    r.success()
                else:
                    SERVICES.add(service)
                    failure_str =f'Service deletion did not return 200, instead {r.status_code}'
                    logging.warning(failure_str)
                    r.failure(failure_str)
            self.interrupt()

        @task(1)
        @tag('error', 'delete', '404', 'delete_service_404_no_service')
        def delete_service_404_no_service(self):
            with self.client.delete(f"/oauth2/service/not_service_id",
                                    verify=False,
                                    allow_redirects=False,
                                    catch_response=True) as r:
                if r.status_code == 404:
                    logging.error("service deletion: error code 404 returned as expected")
                    r.success()
                else:
                    failure_str = f"Service deletion: did not return code 404. Instead: {r.status_code}"
                    logging.warning(failure_str)
                    r.failure(failure_str)
            self.interrupt()
            
    @task(1)
    class GetService(TaskSet):
        @task(1)
        @tag('correct', 'get', '200', 'get_service_200')
        def get_service_200(self):

            try:
                service = SERVICES.choice()
            except KeyError:
                self.interrupt()
            with self.client.get(f"/oauth2/service/{service.serviceId}",
                                 verify=False,
                                 allow_redirects=False,
                                 catch_response=True) as r:
                if r.status_code == 200:
                    logging.info(f"Got service: {service!r}")
                    r.success()
                else:
                    failure_str = f'Service get did not return code 200. Instead: {r.status_code}'
                    logging.warning(failure_str)
                    r.failure(failure_str)
            self.interrupt()

        @task(1)
        @tag('error', 'get', '404', 'get_service_404_no_service')
        def get_service_404_no_service(self):
            with self.client.get(f"/oauth2/service/none",
                                 verify=False,
                                 allow_redirects=False,
                                 catch_response=True) as r:
                if r.status_code == 404:
                    logging.error("Tried to get the service with bad id, status 404 as expected.")
                    r.success()
                else:
                    failure_str = f'Get service with bad id got unexpected status code {r.status_code}'
                    logging.warning(failure_str)
                    r.failure(failure_str)
            self.interrupt()
            
    @task(1)
    class GetServicePage(TaskSet):
        @task(1)
        @tag('correct', 'get', '200', 'get_service_page_200')
        def get_service_page_200(self):
            with self.client.get(f"/oauth2/service", params={'page': '1'},
                                 verify=False,
                                 allow_redirects=False,
                                 catch_response=True) as r:
                if r.status_code == 200:
                    logging.info(f"Got service page with status_code 200.")
                    r.success()
                else:
                    failure_str =f'Service page get did not return code 200. Instead: {r.status_code}'
                    logging.warning(failure_str)
                    r.failure(failure_str)
            self.interrupt()

        @task(1)
        @tag('error', 'get', '400', 'get_service_page_400_no_page')
        def get_service_page_400_no_page(self):
            with self.client.get("/oauth2/service", params={},
                                 verify=False,
                                 allow_redirects=False,
                                 catch_response=True) as r:
                if r.status_code == 400:
                    logging.error("Called service page without page, status 400 as expected.")
                    r.success()
                else:
                    failure_str = f"service page get did not return code 400. Instead: {r.status_code}"
                    logging.warning(failure_str)
                    r.failure(failure_str)
            self.interrupt()
