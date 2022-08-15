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

> Requirements: 

- Python >= 3.9 and pip installed
- Docker installed
- Debugfs mounted ( sudo mount -t debugfs debugfs /sys/kernel/debug )
- Linux kernel headers installed
    - Ubuntu/Debian : apt-get install -y linux-headers-$(uname -r)
    - CentOs : yum install -y kernel-devel
    - Fedora : dnf install -y kernel-devel
### Using a demo Java application in Docker

> Steps : 

1. Install arvos cli

    ```
    pip install arvos
    ```

2. Make sure the port 8080 is not used, and run arvos 

    ```
    arvos --demo
    ```

3. In a separate terminal, run the following command to generate some workload : 

    ```
    while true; do curl -Ikq http://localhost:8080/sanitize; curl -Ikq http://localhost:8080/xstream; sleep 2; done
    ```

4. Once done, you can check the arvos logs in the console by running `docker logs -f tracer`, or by checking the generated pdf report file under $HOME/arvos-reports/.
### Using your own Java application using Docker

To scan your own Java application, you need to:

1. Build a `jar` file for your application. Your application should be able to run in JVM 17 or 18.

2. Install arvos cli 
    ```
    pip install arvos
    ```
3. Run arvos against your application
    ```
    arvos scan --java 17 --jar target/application.jar --pom pom.xml --trace-period 2 --save-report
    ```

    > You can run the arvos scanner indefinitely by not specifying the --trace-period argument

6. Call a few endpoints of your application multiple times (either using curl .. or a browser)

7. You can either wait for the arvos scan to finish or stop it manually by running : 
    ```
    arvos --stop
    ```
    and check the generated report either on the console by running `docker logs -f tracer`, or as a .pdf file under your home directory.

## Links

- [Arvos CLI](https://github.com/ayoubeddafali/arvos-cli) 