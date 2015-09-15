# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import unittest
import uuid

from cryptography import fernet
import msgpack

import fernet_inspector


class TestFernetInspector(unittest.TestCase):
    def setUp(self):
        # some key values to use for testing
        self.fernet_keys = [fernet.Fernet.generate_key()]
        # build a Fernet crypto object to test with
        fernet_instances = [fernet.Fernet(key) for key in self.fernet_keys]
        self.crypto = fernet.MultiFernet(fernet_instances)

    def _pack_token(self, payload):
        # build a token like keystone would from a list of values
        serialized_payload = msgpack.packb(payload)
        return self.crypto.encrypt(serialized_payload).rstrip('=')

    def test_unpack_token_returns_exception_without_fernet_keys(self):
        self.assertRaises(ValueError,
                          fernet_inspector.unpack_token,
                          uuid.uuid4().hex,
                          [])

    def test_unpack_token_with_payload_as_hex(self):
        payload = [uuid.uuid4().hex, uuid.uuid4().hex]
        token = self._pack_token(payload)
        actual_payload = fernet_inspector.unpack_token(token, self.fernet_keys)
        self.assertEqual(payload, actual_payload)

    def test_unpack_token_with_payload_as_bytes(self):
        first_value = uuid.uuid4().bytes
        second_value = uuid.uuid4().bytes
        payload_as_bytes = [first_value, second_value]
        token = self._pack_token(payload_as_bytes)
        actual_payload = fernet_inspector.unpack_token(token, self.fernet_keys)
        self.assertIn(first_value, actual_payload)
        self.assertIn(second_value, actual_payload)

    def test_unpack_token_with_nested_lists(self):
        first_value = uuid.uuid4().bytes
        second_value = uuid.uuid4().bytes
        third_value = uuid.uuid4().bytes
        payload_as_bytes = [first_value, [second_value, third_value]]

        token = self._pack_token(payload_as_bytes)
        actual_payload = fernet_inspector.unpack_token(token, self.fernet_keys)
        self.assertIn(first_value, actual_payload)
        self.assertIn(second_value, actual_payload[1])
        self.assertIn(third_value, actual_payload[1])
