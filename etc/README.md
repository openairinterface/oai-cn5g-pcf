# Jinj2-generated configuration file

We are switching to the `python3-jinja2` tool in order to generate more complex configuration for our 5G core network functions.

Pre-requisites: install python3 and jinja2 packages:

```bash
sudo apt-get install -y python3 python3-jinja2
# or
sudo yum install -y python3 python3-pip
pip3 install jinja2
```

In a container deployment, you will still have to provide environment variables through a `docker-compose-file` or helm charts, but you can also emulate how the entrypoint behaves locally on your workspace.

## Simple PCF Deployment ##

Create a `test-jinja.sh` file and edit it:

```bash
$ vi test-jinja.sh
cp ./etc/pcf.yaml ./etc/pcf_copy.yaml
export CONFIG_FILE=./etc/pcf_copy.yaml
export MOUNT_CONFIG=NO

export PCF_NAME=PCF
export PCC_RULES_DIR=$(pwd)/policies/pcc_rules
export TRAFFIC_RULES_DIR=$(pwd)/policies/traffic_rules
export POLICY_DECISIONS_DIR=$(pwd)/policies/policy_decisions

export REGISTER_NRF=yes
export CLIENT_HTTP_VERSION=1

export SBI_IF_NAME=eth0
export SBI_PORT_HTTP1=80
export SBI_PORT_HTTP2=8080
export SBI_HTTP_VERSION=1
export SBI_API_VERSION=v2

export NRF_HOST=oai-nrf
export NRF_PORT=80
export NRF_API_VERSION=v1

./scripts/entrypoint.py
$ chmod 755 test-jinja.sh
$ ./test-jinja2.sh 
Configuration file ./etc/smf_copy.conf is ready
```

## List of fields ##
Here is the current list of fields, with their mandatory status and any default values.

**Optional** in these tables mean that the environment variables are optional, not the configuration itself. 
For this information, please refer to the `pcf.yaml` file.

### Allowed Values
The allowed values for each field are described in the `pcf.yaml` file.

### Basic Configuration ###

| Field Name                  | Mandatory / Optional | Default value if any |
|:----------------------------|----------------------|---------------------:|
| PCF_NAME                    | Optional             |              OAI-PCF |
| PCC_RULES_DIR               | Mandatory            |                    - |
| TRAFFIC_RULES_DIR           | Mandatory            |                    - |
| POLICY_DECISIONS_DIR        | Mandatory            |                    - |

### Features ###

| Field Name                  | Mandatory / Optional | Default value if any |
|:----------------------------|----------------------|---------------------:|
| REGISTER_NRF                | Optional             |                   no |
| CLIENT_HTTP_VERSION         | Optional             |                    1 |

### Local PCF SBI Interface

| Field Name       | Mandatory / Optional | Default value if any |
|:-----------------|----------------------|---------------------:|
| SBI_IF_NAME      | Mandatory            |                    - |
| SBI_PORT_HTTP1   | Optional             |                   80 |
| SBI_PORT_HTTP2   | Optional             |                 8080 |
| SBI_HTTP_VERSION | Optional             |                    1 |
| SBI_API_VERSION  | Optional             |                   v2 |


### Next Hop SBI Interfaces

#### NRF

| Field Name      | Mandatory / Optional | Default value if any |
|:----------------|----------------------|---------------------:|
| NRF_HOST        | Optional             |              oai-nrf |
| NRF_PORT        | Optional             |                   80 |
| NRF_API_VERSION | Optional             |                   v1 |
