from locust import HttpUser, task, TaskSet, tag
from locust.exception import RescheduleTask

import logging
from uuid import uuid4
from dataclasses import dataclass, field, replace

__all__ = ['USERS', 'User', 'UserRegistration']

# Documentation https://www.networknt.com/service/oauth/service/user/

USERS = set()


@dataclass(init=True, repr=True, eq=False)
class User:
    userId: str = field(default_factory=lambda: str(uuid4())[:8], repr=True, hash=True)
    firstName: str = field(default_factory=lambda: str(uuid4())[:32], repr=False, hash=False)
    lastName: str = field(default_factory=lambda: str(uuid4())[:32], repr=False, hash=False)
    userType: str = field(default="admin", repr=True, hash=False)
    email: str = field(default_factory=lambda: str(uuid4()), repr=False, hash=False)
    password: str = field(default_factory=lambda: str(uuid4()), repr=False, hash=False)

    def to_dict(self):
        return {'userId': self.userId,
                'userType': self.userType,
                'firstName': self.firstName,
                'lastName': self.lastName,
                'email': self.email,
                'password': self.password,
                'passwordConfirm': self.password}


class UserRegistration(HttpUser):

    fixed_count = 1
    host = 'https://localhost:6885'

    @task(1)
    class RegisterUser(TaskSet):

        @task(1)
        @tag('correct', 'register', '200')
        def register_user_200(self):
            user = User()
            with self.client.post("/oauth2/user", data=user.to_dict(),
                                  verify=False, allow_redirects=False,
                                  catch_response=True) as r:

                if r.status_code == 200:
                    logging.info(f"Registered user: {user!r}")
                    USERS.add(user)
                    r.success()
                else:
                    del user
                    logging.info(f"User registration did not return code 200, instead {r.status_code}, {r.text}")
                    r.failure("User registration did not return code 200")
                self.interrupt()

    @task(1)
    class UpdateUser(TaskSet):
        @task(1)
        @tag('correct', 'update', '200')
        def update_user_200(self):
            try:
                user = USERS.pop()
            except KeyError:
                  self.interrupt
            userupdate = replace(user, userId=user.userId)
            with self.client.put("/oauth2/user", data=userupdate.to_dict(),
                                  verify=False, allow_redirects=False,
                                  catch_response=True) as r:

                if r.status_code == 200:
                     USERS.add(userupdate)
                     logging.info(f"updated user: {userupdate!r}")
                     del user
                     r.success()
                else:
                     USERS.add(user)
                     del userupdate
                     logging.info(f"User updation did not return code 200, instead {r.status_code}, {r.text}")
                     r.failure(f"User updation did not return code 200", {r.status_code})
                self.interrupt()

        @task(1)
        @tag('error', 'update', '404')
        def update_user_404(self):
            try:
                user = USERS.pop()
                USERS.add(user)
            except KeyError:
                self.interrupt()
            userupdate = replace(user, userId="")

            with self.client.put("/oauth2/user", json=userupdate.to_dict(),
                                 verify=False, allow_redirects=False,
                                 catch_response=True) as r:
                if r.status_code == 404:
                    logging.info(f"User update without id failed as expected, 404")
                    r.success()
                else:
                    failstr = f"Unexpected status code when updating user without id: {r.status_code}"
                    logging.info(failstr)
                    r.failure(failstr)
                self.interrupt()
          
    @task(1)
    class GetUser(TaskSet):
        @task(1)
        @tag('correct', 'get', '200')
        def get_user_200(self):
            try:
                user = USERS.pop()
                USERS.add(user)
            except KeyError:
                self.interrupt()
            r = self.client.get(f"/oauth2/user/{user.userId}", verify=False, allow_redirects=False)
            if r.status_code == 200:
                logging.info(f"Got user: {user!r}")
            else:
                logging.info(f'user get did not return code 200. Instead: {r.status_code}')
            self.interrupt()                  