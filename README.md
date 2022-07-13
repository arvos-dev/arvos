# AI- and Risk-based Vulnerability Management for Trustworthy Open Source Adoption (ARVOS)

## Overview

The goal of this project is to support uptake of open source software by providing support to identify which of all disclosed vulnerabilities are a real concern for them and how to prioritize their vulnerability management efforts. This will be done by developing APIs, algorithms, and tools for detecting the use of vulnerable functionality in software and prioritizing what vulnerabilities to mitigate.

Vulnerabilities in third-party or open-source software is not a new problem, but as organizations, society, and even our critical infrastructure become increasingly dependent on software-based systems, handling vulnerabilities becomes more important. At the same time, the number of vulnerabilities reported by the US National Vulnerability Database (NVD) is, since 2017, in the order of 15k-18k each year, an increase from 4k-8k between 2005-2016.

To tackle these challenges, the ARVOS project will first extract vulnerable symbols by correlating Git commit history with the CVE database.
Then, eBPF probes used at runtime, either in testing or in production, to measure if these symbols are actually used.
This helps contextualize vulnerabilities, identify which are related to real threats, which in turn helps prioritize security patching.

## Current Focus

The ARVOS project started by conducting user interview and is now moving into the technical validation phase.
The focus is on answering the following high-level questions:

* Can we prove that the ARVOS approach brings benefits in comparison to a static analysis approach?
* Can we package ARVOS in an easy-to-use manner?
* Are there any technical barriers (e.g., performance) to overcome?

## High-Level Requirements

### Environment

We first focus on containerized CI/CD environments, specifically the Docker container engine.
In a next iteration, we will focus on containerized production environments, specifically Kubernetes using Docker as container engine.

### Programming Language

We first focus on the Java programming language for two reasons:

1. It is a programming language frequently used in the backend.
2. It allows an apples-to-apples comparison with static vulnerability management approaches. This allows us to measure ARVOS's benefits.

In a next iteration, we will focus on Python, which cannot be easily addressed with static approaches.

Later, we will also tackle JavaScript / NodeJS, for the same reasons as Python.

### Packaging

ARVOS needs to be easy to install.

The exact CLI and output (e.g., human-readable, colored terminal, CSV, JSON) are left as hypothesis to be answered during the technical validation.

## Running ARVOS PoC

### Using a demo Java application in Docker

> Requirements: 

- Python >= 3.9 and pip installed
- Docker installed
- Debugfs mounted ( sudo mount -t debugfs debugfs /sys/kernel/debug )


> Steps : 

1. Install arvos cli

    ```
    pip install arvos
    ```

2. Run arvos 

    ```
    arvos --demo --save-report
    ```

3. In a separate terminal, run the following command to generate some workload : 

    ```
    while true; do curl -Ikq http://localhost:8080/vulnerable; curl -Ikq http://localhost:8080/decompress; sleep 2; done
    ```

4. Once done, you can check the arvos logs in the console by running `docker logs -f tracer`, or by checking the generated pdf report file under $HOME/arvos-reports/.
### Using your own Java application using Docker

To scan your own Java application, you need to:

1. Build a `jar` file for your application. Your application should be able to run in JVM 17.
2. Create a Docker image for your application based on the `ayoubensalem/jdk-docker-jstack` Docker image. Create a `Dockerfile` that looks like the below in the same directory where your `jar` file resides.
    ```
    FROM ayoubensalem/jdk-docker-jstack
    COPY YOUR-APPLICATION.jar ./application.jar
    ```
3. Replace `YOUR-APPLICATION` in the above two file with the name of your `jar` file.
4. Build the Docker image
    ```
    docker build -t YOUR-DOCKER-REGISTRY/APPLICATION-IMAGE-NAME .
    ```
5. In a first terminal, run your application using Docker.
    ```
    docker run -d --name app --net host  YOUR-DOCKER-REGISTRY/APPLICATION-IMAGE-NAME
    ```
6. Continuously call a few endppoints of your application.
7. In a second terminal, run the following commands to generate stack traces and to run the tracer application `arvos-poc`.

    - Make sure the debugfs is mounted : 
        ```
        sudo mount -t debugfs debugfs /sys/kernel/debug
        ```
    - Run arthas diagnosis tool :
        ```
        export APP=app
        docker exec -it $APP /bin/bash -c "/jdk/bin/java -jar arthas-boot.jar --attach-only --select application.jar"
        ``` 
    - Run the tracer app : 
        ```
        docker run -it --rm --net host -e TRACE_TIME=2 -v /sys/kernel/debug:/sys/kernel/debug:rw -v /lib/modules/$(uname -r):/lib/modules/$(uname -r) -v /usr/src:/usr/src --privileged --pid container:$APP ayoubensalem/arvos-poc $(docker exec -ti $APP pidof java)
        ```