# 01 - Certificate creation image build

The dockerfile hosted in this directory is used to build the image used to boot Wazuh's single node and multi node stacks.

To create the image, the following command must be executed:

```
$ docker build -t wazuh/wazuh-certs-generator:0.0.1 .
```


# 02 -Deploy Wazuh Docker in single node configuration

This deployment is defined in the `../docker-compose.yml` file with one Wazuh manager containers, one Wazuh indexer containers, and one Wazuh dashboard container. It can be deployed by following these steps: 

1) Run the certificate creation script:
```
$ docker-compose -f generate-indexer-certs.yml run --rm generator
```
2) Start the environment with docker-compose:

- In the foregroud:
```
$ docker-compose up
```
- In the background:
```
$ docker-compose up -d
```

The environment takes about 1 minute to get up (depending on your Docker host) for the first time since Wazuh Indexer must be started for the first time and the indexes and index patterns must be generated.
