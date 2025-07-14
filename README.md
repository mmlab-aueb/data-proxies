# Enabling semi-trusted proxies for Data Spaces
This repository includes the source code used for the evaluation of the solution
presented in the paper "Enabling semi-trusted proxies for Data Spaces" (under review)

## Set up
Install the following dependencies

```bash
python3 -m pip install cryptography
python3 -m pip install jwcrypto
```

Execute `initialize.py` to generate the signing and verification keys, as well as
the test vectors

```bash
python3 initialize.py
```

## Benchmarking
### Signing

Execute the sign script 

```bash
python3 sign.py
```


### Selective disclosure and verifying

Execute the verification script 

```bash
python3 verify.py
```

The script randomly reveals 5 to 50 attributes and performs signature verification 