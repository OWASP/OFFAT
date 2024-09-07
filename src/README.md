# OFFAT - OFFensive Api Tester

![OffAT Logo](/assets/images/logos/offat-3.png)

Automatically Tests for vulnerabilities after generating tests from openapi specification file. Project is in Beta stage, so sometimes it might crash while running.

![UnDocumented petstore API endpoint HTTP method results](/assets/images/tests/offat-v0.5.0.png)

>  [!WARNING]  
>  At the moment HTTP 2/3 aren't supported since fasthttpclient is used under the hood to increase performance.
>  Visit [FastHTTP README](https://github.com/valyala/fasthttp) for more details

## Security Checks

- [x] Restricted HTTP Method/Verb
- [x] BOLA
- [x] BOPLA/Mass Assignment
- [x] SQL Injection
- [x] Command Injection
- [x] XSS/HTML Injection
- [x] SSTI
- [x] SSRF
- [x] Data Exposure (Detects Common Data Exposures)
- [ ] Broken Access Control
- [ ] Broken Authentication

## Features

- Supports openAPI specification (OAS) Doc
- Few Security Checks from OWASP API Top 10
- Automated Testing
- User Config Based Testing
- API for Automating tests and Integrating Tool with other platforms/tools
- CLI tool
- Proxy Support
- Hardened Docker Images
- Open Source Tool with MIT License
- Trigger scans in CI/CD using GitHub Action

> Swagger files are not supported at the moment

## Github Action

- Create github action secret `url` for your repo
- Setup github action workflow in your repo `.github/workflows/offat.yml`

```yml
name: OWASP OFFAT Sample Workflow

on:
  push:
    branches:
      - dev
      - main

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - name: "download OAS file"
        run: curl ${url} -o /tmp/oas.json
        env:
          url: ${{ secrets.url }}

      - name: "OWASP OFFAT CICD Scanner"
        uses: OWASP/OFFAT@main # OWASP/OFFAT@v0.20.0
        with:
          file: /tmp/oas.json # or ${{ secrets.url }}
          rate_limit: 120
          artifact_retention_days: 1
```

> Prefer locking action to specific version `OWASP/OFFAT@v0.20.0` instead of using `OWASP/OFFAT@main` and bump OFFAT action version after testing.

## Disclaimer

The disclaimer advises users to use the open-source project for ethical and legitimate purposes only and refrain from using it for any malicious activities. The creators and contributors of the project are not responsible for any illegal activities or damages that may arise from the misuse of the project. Users are solely responsible for their use of the project and should exercise caution and diligence when using it. Any unauthorized or malicious use of the project may result in legal action and other consequences.

[Read More](./DISCLAIMER.md)

## Installation

### Using Go

- Clone repository

    ```bash
    git clone https://github.com/OWASP/OFFAT
    ```

- Go source code is stored in src directory

    ```bash
    cd src
    ```

- Run Go install command

    ```bash
    go install ./...
    ```

### Using Containers

### Docker

- CLI Tool

  ```bash
  docker run --rm dmdhrumilmistry/offat -h
  ```

## Start OffAT

### CLI Tool

- Run offat

  ```bash
  offat -f oas.json              # using file
  offat -f https://example.com/docs.json  # using url
  ```

  > JSON and YAML formats are supported

- To get all the commands use `help`

  ```bash
  offat -h
  ```

- Save result in `json`

  ```bash
  offat -f oas.json -o output.json
  ```

- Get curl command for making requests

  ```bash
  jq -r '.[].concurrent_response.response.curl_command' output.json
  ```
  > `jq` tool is required to run above command

- Run tests only for endpoint paths matching regex pattern

  ```bash
  offat -f oas.yml -pr '/user'
  ```

- Add headers to requests

  ```bash
  offat -f oas.json -H 'Accept: application/json' -H 'Authorization: Bearer YourJWTToken'
  ```

- Run Test with Requests Rate Limited

  ```bash
  offat -f oas.json -r 1000
  ```

  > `r`: requests rate limit per second

- Use along with proxy

  ```bash
  # without ssl check
  offat -f oas.json -p http://localhost:8080 -o output.json

  # without ssl check
  offat -f oas.json -p http://localhost:8080 -o output.json -ns
  ```

  > Make sure that proxy can handle multiple requests at the same time

- For Data Leak detection, create a new data leakage detection file from this sample file [owasp-offat-data-leak-patterns.yml](https://gist.github.com/dmdhrumilmistry/cd43ac90fa28f3c6d9c1b87c56586103)
  
  ```bash
  offat -f oas.yaml -dl owasp-offat-data-leak-patterns.yml
  ```

>  [!WARNING]  
>  Remember to include only patterns whose data can be probably found in your APIs, 
>  since detection process can lead to CPU spikes.

<!-- - Use user provided inputs for generating tests

  ```bash
  offat -f oas.json -tdc test_data_config.yaml
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
  ``` -->

### Open In Google Cloud Shell

- Temporary Session

  [![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://shell.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/OWASP/OFFAT.git&ephemeral=true&show=terminal&cloudshell_print=./DISCLAIMER.md)

- Perisitent Session

  [![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://shell.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/OWASP/OFFAT.git&ephemeral=false&show=terminal&cloudshell_print=./DISCLAIMER.md)

## Have any Ideas 💡 or issue

Create an issue *OR* fork the repo, update script and create a Pull Request

## Contributing

Refer [CONTRIBUTIONS.md](/CONTRIBUTING.md) for contributing to the project.

## LICENSE

OWASP OFFAT is distributed under `MIT` License. Refer [License](/LICENSE.md) for more information.
