# pullimage

Pulling container images are complicated. This is a script to show you the gross inner workings of pulling stuff from a docker registry.

For educational purposes mostly.

(WIP, use as reference or proof of concept code.)

## usage

by default, it pulls from docker hub like `docker pull` does.

```
./pullimage.py ubuntu:22.04
```

specify registry:

```
./pullimage.py ghcr.io/apache/airflow/main/ci/python3.10
```

it will show you some info (like from the schema or manifest files), then download the image to `downloads/`

