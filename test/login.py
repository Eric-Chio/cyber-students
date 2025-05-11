from json import dumps
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from tornado.ioloop import IOLoop
from tornado.web import Application

from .base import BaseTest

from api.handlers.login import LoginHandler

import urllib.parse

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import base64
import os
from .conf import pepper  #pepper stored in configuration file


class LoginHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/login', LoginHandler)])
        super().setUpClass()

    @coroutine
    def register(self):
        # Generate a random salt
        salt = os.urandom(16)

        # Hash the password using Scrypt
        kdf = Scrypt(
            salt = salt,
            length = 32,
            n = 2**14,
            r = 8,
            p = 1,
            backend = default_backend()
        )
        password_bytes = self.password.encode('utf-8')
        peppered_password = password_bytes + pepper # Append the pepper to the password
        hashed_password = kdf.derive(peppered_password)
        hashed_password_b64 = base64.b64encode(hashed_password).decode('utf-8')

        yield self.get_app().db.users.insert_one({
            'email': self.email,
            'password': hashed_password_b64,
            'salt': base64.b64encode(salt).decode('utf-8'),  
            'displayName': 'testDisplayName'
        })

    def setUp(self):
        super().setUp()

        self.email = 'test@test.com'
        self.password = 'testPassword'

        IOLoop.current().run_sync(self.register)

    def test_login(self):
        body = {
          'email': self.email,
          'password': self.password
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertIsNotNone(body_2['token'])
        self.assertIsNotNone(body_2['expiresIn'])

    def test_login_case_insensitive(self):
        body = {
          'email': self.email.swapcase(),
          'password': self.password
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertIsNotNone(body_2['token'])
        self.assertIsNotNone(body_2['expiresIn'])

    def test_login_wrong_email(self):
        body = {
          'email': 'wrongUsername',
          'password': self.password
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(403, response.code)

    def test_login_wrong_password(self):
        body = {
          'email': self.email,
          'password': 'wrongPassword'
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(403, response.code)
