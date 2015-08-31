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

import argparse
import os
import uuid

from cryptography import fernet
import msgpack
import six


class NonExistentKeyRepository(Exception):
    code = 400
    message_format = "Key repository location doesn't exist."


class EmptyKeyRepository(Exception):
    code = 400
    message_format = "Key repository is empty."


class InvalidToken(Exception):
    code = 400
    message_format = ("Unable to decrypt the token with the specified key"
                      " repository.")


def get_args():
    """Get arguments from the user."""
    parser = argparse.ArgumentParser(
        prog='fernet-inspector',
        description='Inspect the contents of a Keystone Fernet token from '
                    'the host it was issued from.')
    parser.add_argument('-t', '--token', type=str, required=True,
                        help='token to decrypt')
    parser.add_argument('-k', '--key-repository', type=str,
                        default='/etc/keystone/fernet-keys/',
                        help='location of Fernet key repository.')
    args = parser.parse_args()
    return args.token, args.key_repository


def unpack_token(fernet_token, key_repository):
    """Attempt to unpack a token using the supplied key repository.

    :param fernet_token: token to unpack
    :type fernet_token: string
    :param key_repository: location path of local Fernet key repository
    :type fernet_token: string
    :returns: the token payload
    :raises: Exception in the event the token can't be unpacked

    """

    keys = _load_keys(key_repository)

    if not keys:
        raise EmptyKeyRepository()

    # create a list of fernet instances
    fernet_instances = [fernet.Fernet(key) for key in keys]
    # create a encryption/decryption object from the fernet keys
    crypt = fernet.MultiFernet(fernet_instances)

    # attempt to decode the token
    token = six.moves.urllib.parse.unquote(six.binary_type(fernet_token))
    try:
        serialized_payload = crypt.decrypt(token)
    except fernet.InvalidToken():
        raise InvalidToken
    payload = msgpack.unpackb(serialized_payload)
    return payload


def _load_keys(key_repository):
    """Load keys from the key repository."""
    # validate the repository location
    if not os.path.isdir(key_repository):
        raise NonExistentKeyRepository()

    # build a dictionary of key_number:encryption_key pairs
    keys = dict()
    for filename in os.listdir(key_repository):
        path = os.path.join(key_repository, str(filename))
        if os.path.isfile(path):
            with open(path, 'r') as key_file:
                try:
                    key_id = int(filename)
                except ValueError:
                    pass
                else:
                    keys[key_id] = key_file.read()

    return [keys[x] for x in sorted(keys.keys(), reverse=True)]


def _convert_to_hex(string_to_convert):
    try:
        return uuid.UUID(bytes=string_to_convert).hex
    except ValueError:
        return string_to_convert
    except TypeError:
        return string_to_convert


def main():

    # get arguments
    fernet_token, key_repository = get_args()

    # unpack the token
    payload = unpack_token(fernet_token, key_repository)
    translated_payload = []
    for item in payload:
        if isinstance(item, list):
            translated_item = []
            for i in item:
                translated_item.append(_convert_to_hex(i))
            translated_payload.append(translated_item)
        else:
            translated_payload.append(_convert_to_hex(item))

    # present token values
    print translated_payload


if __name__ == '__main__':
    main()
