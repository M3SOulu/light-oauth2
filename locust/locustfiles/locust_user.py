from locust import HttpUser, task, TaskSet, tag
from locust.exception import RescheduleTask

import logging
from uuid import uuid4
from dataclasses import dataclass, field, replace

__all__ = ['USERS', 'User', 'UserRegistration']

# Documentation https://www.networknt.com/service/oauth/service/user/

USERS = set()


@dataclass
class User:
    userId: str = field(default_factory=lambda: str(uuid4())[:8], repr=True, hash=True)
    firstName: str = field(default_factory=lambda: str(uuid4())[:32], repr=False, hash=False)
    lastName: str = field(default_factory=lambda: str(uuid4())[:32], repr=False, hash=False)
    userType: str = field(default="admin", repr=True, hash=False)
    email: str = field(default='first.last@oulu.fi', repr=False, hash=False)
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
    pass
