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

You should be able to pass a Keystone Fernet token to `inspector.py` and get
the resulting payload:

```
> python inspector.py -t <token-to-decrypt>
[2, 'b03ed914036b46b394c940419e12da0f', 1, '5aced855355a48f6aed86e403b9a9860', 1441038294.957523, ['de9556fea4224dd988954a67715a2a01']]
```

Now you can map to the appropriate payload based on the first element of the
payload. The first element is `2` in this case, which means we are dealing with
a `ProjectScopedPayload` of the
`keystone.token.providers.fernet.token_formatter.py:TokenFormatter` class.
