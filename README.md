# fernet-inspector
A tool for inspecting the contents of a Fernet token.

## Example Usage

```
> python inspector.py -h
usage: fernet-inspector [-h] -t TOKEN [-k KEY_REPOSITORY]

Inspect the contents of a Keystone Fernet token from the host it was issued
from.

optional arguments:
  -h, --help            show this help message and exit
  -t TOKEN, --token TOKEN
                        token to decrypt
  -k KEY_REPOSITORY, --key-repository KEY_REPOSITORY
                        location of Fernet key repository.
```
