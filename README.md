# OWASP OFFAT

OWASP OFFAT (OFFensive Api Tester) is created to automatically test API for common vulnerabilities after generating tests from openapi specification file. It provides feature to automatically fuzz inputs and use user provided inputs during tests specified via YAML config file.

![UnDocumented petstore API endpoint HTTP method results](https://owasp.org/OFFAT/assets/images/tests/offat-v0.5.0.png)

## Demo

[![asciicast](https://asciinema.org/a/LFXLILNkf7Gce5uCuJydplbEd.svg)](https://asciinema.org/a/LFXLILNkf7Gce5uCuJydplbEd)

## Security Checks

-   Restricted HTTP Methods
-   SQLi
-   BOLA
-   Data Exposure
-   BOPLA / Mass Assignment
-   Broken Access Control
-   Basic Command Injection
-   Basic XSS/HTML Injection test

## Features

-   Few Security Checks from OWASP API Top 10
-   Automated Testing
-   User Config Based Testing
-   API for Automating tests and Integrating Tool with other platforms/tools
-   CLI tool
-   Dockerized Project for Easy Usage
-   Open Source Tool with MIT License

## Try Tool

-   Install Tool using pip

```bash
python -m pip install offat
```

-   Run Tool

```bash
offat -f swagger_file.json
```

-   For more usage options read [README.md](https://github.com/OWASP/OFFAT/blob/main/src/README.md)
