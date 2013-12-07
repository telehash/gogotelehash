# go-interop-test

## Usage

`go-interop-test --port [PORT] --seed [SEED_FILE] --rsa-key [KEY_FILE] run`

Logging can be turned on by setting the `TH_LOG_ALL` environment variable to `notice` or `debug`.
When logging at the `notice` level the switch will emit some basic statistics.

## Running the tests

You will want to run the test with `TH_LOG_ALL=notice`.
Like this you will be able to see if lines are properly maintained.

### Running as a seed:

`TH_LOG_ALL=notice go-interop-test --port 45454 run`

The content for a seed file will be printed to `STDOUT`.

### Running as a normal peer:

`TH_LOG_ALL=notice go-interop-test --seed SEED_FILE run`

`SEED_FILE` must point to a file containing a list of seeds.

## Options

### `--port`

The port the switch will bind to.
Defaults to an emphemeral port selected by the OS.

### `--seed`

A JSON file containing a list of seeds.
By default a switch is not seeded.

The seed file has the following format:

```json
[
  {
    "ip": "127.0.0.1",
    "port": 45454,
    "pubkey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzyDcYPeyX6hAzfvXHR3k\nNoPfGRMSpV5D/bheldD1/WReUOkEozPW3fQG1ZaexmZ49Pmua0y/uPcQP6p5Mho3\ncN6N640jfME734brXNzXmHSVQFGqaFxpqCyIlHfhqMlOxJl58x3Cs7yesYpoHrI2\nsVumf5ChI3tM3l1RqPbS8MGNk7cGU8Z7t3Kp69ulehOAFytW/rhINMGWOGWYpCJA\nYjxTIC40PEBgb1S3bvcbcJXFR5se+oas/tlTyqg8BMdfXKDdYT+bg+Zh0Nm4yw/h\nFdWKYXS/qNwpsEOc57H3Cm00kwujtc6CTR/t2UDiO9uEly5BoITlRAeLggeerC5m\n2QIDAQAB\n-----END PUBLIC KEY-----\n"
  }
]
```

### `--rsa-key`

Path to an RSA key file in PEM format.
Defaults to a random RSA key.


## Building from source

To build `go-interop-test` you need to have go 1.1 (or beter) [installed](http://golang.org/doc/install) and setup properly.

```bash
git clone -b develop git@github.com:telehash/gogotelehash.git
cd gogotelehash
make examples
```
