# Testing

First tests have been set up to cover GPG Mailgate with at least basic test
that would be easy to run.  The tests are called "end-to-end", meaning that we
feed some input to GPG Mailgate and inspect the output.

## Running tests

To run tests, use command `make test` or `make unittest`.

Tests produce some helpful logs, so inspect contents of `test/logs` directory
if something goes wrong.

If your system's Python binary isn't found in your `$PATH` or you want to use
a specific binary, use make's macro overriding: `make test
PYTHON=/path/to/python`.

## Key building blocks

- *Test Script* (`test/e2e_test.py`) that orchestrates the other components.
  It performs test cases described in the *Test Configuration*.  It spawns
  *Test Mail Relay* and *GPG Mailgate* in appropriate order.
- *Test Mail Relay* (`test/relay.py`), a simplistic mail daemon that only
  supports the happy path.  It accepts a mail message and prints it to
  stdandard output.
- *Test Configuration* (`test/e2e.ini`) specifies test cases: their input,
  expected results and helpful documentation.  It also specifies the port that
  the *Test Mail Relay* should listen on.

## Limitations

Currently tests only check if the message has been encrypted, without
verifying that the correct key has been used.  That's because we don't know
(yet) how to have a reproducible encrypted message.  Option
`--faked-system-time` wasn't enough to produce identical output.

## Troubleshooting

When things go wrong, be sure to study `test/logs/e2e.log` and
`test/logs/gpg-mailgate.log` files -- they contain some useful information.
