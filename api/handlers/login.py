from datetime import datetime, timedelta
from time import mktime
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from uuid import uuid4

from .base import BaseHandler

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import base64
from ..conf import pepper  #pepper stored in configuration file

class LoginHandler(BaseHandler):

    @coroutine
    def generate_token(self, email):
        token_uuid = uuid4().hex
        expires_in = datetime.now() + timedelta(hours=2)
        expires_in = mktime(expires_in.utctimetuple())

        token = {
            'token': token_uuid,
            'expiresIn': expires_in,
        }

        yield self.db.users.update_one({
            'email': email
        }, {
            '$set': token
        })

        return token

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
        except:
            self.send_error(400, message='You must provide an email address and password!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        # Retrieve user data, including hashed password, salt, and encrypted displayName
        user = yield self.db.users.find_one({
          'email': email
        }, {
            'password': 1,
            'salt': 1,
            'displayName': 1
        })

        if user is None:
            self.send_error(403, message='The email address and password are invalid!')
            return

        # Verify password: check if salt exists (hashed password)
        password_match = False
        try:
            stored_hash = base64.b64decode(user['password'])
            salt = base64.b64decode(user['salt'])
            
            kdf = Scrypt(
                salt = salt,
                length = 32,
                n = 2**14,
                r = 8,
                p = 1,
                backend = default_backend()
            )
            password_bytes = password.encode('utf-8')
            peppered_password = password_bytes + pepper # Append the pepper to the password
            hashed_password = kdf.derive(peppered_password)
            #hashed_password_b64 = base64.b64encode(hashed_password).decode('utf-8')

            password_match = (hashed_password == stored_hash)
        except Exception:
            password_match = False
        
        if not password_match:
            self.send_error(403, message='The email address or password are incorrect!')
            return

        token = yield self.generate_token(email)

        self.set_status(200)
        self.response['token'] = token['token']
        self.response['expiresIn'] = token['expiresIn']

        self.write_json()
