# OFFAT - OFFensive Api Tester

![OffAT Logo](/assets/images/logos/offat-3.png)

Automatically Tests for vulnerabilities after generating tests from openapi specification file. Project is in Beta stage, so sometimes it might crash while running.

![UnDocumented petstore API endpoint HTTP method results](/assets/images/tests/offat-v0.5.0.png)

## Security Checks

-   [x] Restricted HTTP Methods
-   [x] SQLi
-   [x] BOLA (Might need few bug fixes)
-   [x] Data Exposure (Detects Common Data Exposures)
-   [x] BOPLA / Mass Assignment
-   [x] Broken Access Control
-   [x] Basic Command Injection
-   [x] Basic XSS/HTML Injection test
-   [ ] Broken Authentication

## Features

-   Few Security Checks from OWASP API Top 10
-   Automated Testing
-   User Config Based Testing
-   API for Automating tests and Integrating Tool with other platforms/tools
-   CLI tool
-   Proxy Support
-   Dockerized Project for Easy Usage
-   Open Source Tool with MIT License

## Demo

[![asciicast](https://asciinema.org/a/9MSwl7UafIVT3iJn13OcvWXeF.svg)](https://asciinema.org/a/9MSwl7UafIVT3iJn13OcvWXeF)

## PyPi Downloads

| Period |                                                                                               Count                                                                                                |
| :----: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------: |
| Weekly | [![Downloads](https://static.pepy.tech/personalized-badge/offat?period=week&units=international_system&left_color=black&right_color=orange&left_text=Downloads)](https://pepy.tech/project/offat)  |
| Monthy | [![Downloads](https://static.pepy.tech/personalized-badge/offat?period=month&units=international_system&left_color=black&right_color=orange&left_text=Downloads)](https://pepy.tech/project/offat) |
| Total  | [![Downloads](https://static.pepy.tech/personalized-badge/offat?period=total&units=international_system&left_color=black&right_color=orange&left_text=Downloads)](https://pepy.tech/project/offat) |

## Disclaimer

The disclaimer advises users to use the open-source project for ethical and legitimate purposes only and refrain from using it for any malicious activities. The creators and contributors of the project are not responsible for any illegal activities or damages that may arise from the misuse of the project. Users are solely responsible for their use of the project and should exercise caution and diligence when using it. Any unauthorized or malicious use of the project may result in legal action and other consequences.

[Read More](./DISCLAIMER.md)

## Installation

### Using pip

-   Install main branch using pip

    ```bash
    python3 -m pip install git+https://github.com/OWASP/OFFAT.git
    ```

-   Install Release from PyPi

    ```bash
    python3 -m pip install offat        # only cli tool
    python3 -m pip install offat[api]   # cli + api
    ```

### Using Containers

### Docker

-   Build Image

    ```bash
    make build-local-images
    ```

-   CLI Tool

    ```bash
    docker run --rm dmdhrumilmistry/offat
    ```

-   API

    ```bash
    docker compose up -d
    ```

    > POST `openapi` documentation to `/api/v1/scan/` endpoint with its valid `type` (json/yaml); `job_id` will be returned.

### Manual Method

-   Open terminal

-   Install git package

    ```bash
    sudo apt install git python3 -y
    ```

-   Install [Poetry](https://python-poetry.org/docs/master#installing-with-the-official-installer)

-   clone the repository to your machine

    ```bash
    git clone https://github.com/OWASP/OFFAT.git
    ```

-   Change directory

    ```bash
    cd offat
    ```

-   install with poetry

    ```bash
    # without options
    poetry install
    ```

## Start OffAT

### API

-   Start API Server

    ```bash
    python -m offat.api

    # OR

    offat-api
    ```

-   API Documentation can be found at <http://localhost:8000/docs>

### CLI Tool

-   Run offat

    ```bash
    offat -f swagger_file.json              # using file
    offat -f https://example.com/docs.json  # using url
    ```

-   To get all the commands use `help`

    ```bash
    offat -h
    ```

-   Save result in `json`, `yaml` or `html` formats.

    ```bash
    offat -f swagger_file.json -o output.json           # json
    offat -f swagger_file.json -o output.html -of html  # html
    offat -f swagger_file.json -o output.yaml -of yaml  # yaml
    ```

> `json` format is default output format.
> `yaml` format needs to be sanitized before usage since it dumps data as python objects.
> `html` format needs more visualization.

-   Run tests only for endpoint paths matching regex pattern

    ```bash
    offat -f swagger_file.json -pr '/user'
    ```

-   Add headers to requests

    ```bash
    offat -f swagger_file.json -H 'Accept: application/json' -H 'Authorization: Bearer YourJWTToken'
    ```

-   Run Test with Requests Rate Limited

    ```bash
    offat -f swagger_file.json -rl 1000 -dr 0.001
    ```

    > `rl`: requests rate limit, `dr`: delay between requests

-   Use along with proxy

```bash
offat -f swagger_file.json -p http://localhost:8080 --no-ssl -o output.json
```

> Make sure that proxy can handle multiple requests at the same time

-   Use user provided inputs for generating tests

    ```bash
    offat -f swagger_file.json -tdc test_data_config.yaml
    ```

    `test_data_config.yaml`

    ```yaml
    actors:
        - actor1:
              request_headers:
                  - name: Authorization
                    value: Bearer [Token1]
                  - name: User-Agent
                    value: offat-actor1

              query:
                  - name: id
                    value: 145
                    type: int
                  - name: country
                    value: uk
                    type: str
                  - name: city
                    value: london
                    type: str

              body:
                  - name: name
                    value: actorone
                    type: str
                  - name: email
                    value: actorone@example.com
                    type: str
                  - name: phone
                    value: +11233211230
                    type: str

              unauthorized_endpoints: # For broken access control
                  - "/store/order/.*"

        - actor2:
              request_headers:
                  - name: Authorization
                    value: Bearer [Token2]
                  - name: User-Agent
                    value: offat-actor2

              query:
                  - name: id
                    value: 199
                    type: int
                  - name: country
                    value: uk
                    type: str
                  - name: city
                    value: leeds
                    type: str

              body:
                  - name: name
                    value: actortwo
                    type: str
                  - name: email
                    value: actortwo@example.com
                    type: str
                  - name: phone
                    value: +41912312311
                    type: str
    ```

> If you're using Termux or windows, then use `pip` instead of `pip3`.  
> Few features are only for linux os, hence they might not work on windows and require admin priviliges.

### Open In Google Cloud Shell

-   Temporary Session  
    [![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://shell.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/OWASP/OFFAT.git&ephemeral=true&show=terminal&cloudshell_print=./DISCLAIMER.md)
-   Perisitent Session  
    [![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://shell.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/OWASP/OFFAT.git&ephemeral=false&show=terminal&cloudshell_print=./DISCLAIMER.md)

## Have any Ideas 💡 or issue

-   Create an issue
-   Fork the repo, update script and create a Pull Request

## Contributing

Refer [CONTRIBUTIONS.md](/CONTRIBUTING.md) for contributing to the project.

## LICENSE

Offat is distributed under `MIT` License. Refer [License](/LICENSE.md) for more information.
