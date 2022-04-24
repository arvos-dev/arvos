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

1. In a terminal run the demo Java application (containing netty dependencies) using Docker.

    ```
    docker run -d --name app -p 8080:8080 -v $PWD/logs:/stack_logs moule3053/netty-demo
    ```
2. After a few moments, run the following command to call two endpoints of the application.

    ```
    while true; do curl http://localhost:8080/actuator/health; curl http://localhost:8080/actuator/info; done
    ```
3. In a second terminal, run the following commands to generate stack traces and to run the tracer application `arvos-poc`.

    ```
    export APP=app
    docker exec -it $APP /bin/bash -c "/get_stack_traces.sh" && docker pull moule3053/arvos-poc && docker run -it --rm -v $PWD/logs:/stack_logs -v /lib/modules/$(uname -r):/lib/modules/$(uname -r) -v /usr/src:/usr/src --privileged --pid container:$APP moule3053/arvos-poc $(docker exec -ti $APP pidof java)
    ```
4. If everything goes well, you should see something like the following figure.
   ![Screenshot from 2022-02-11 09-31-27](https://user-images.githubusercontent.com/14330171/153579834-872f6007-ff5a-43aa-8898-6613cd350ce0.png)

### Using your own Java application using Docker

To scan your own Java application, you need to:

1. Build a `jar` file for your application. Your application should be able to run in JVM 17.
2. Create a Docker image for your application based on the `moule3053/jdk-docker-jstack` Docker image. Create a `Dockerfile` that looks like the below in the same directory where your `jar` file resides.
    ```
    FROM moule3053/jdk-docker-jstack
    RUN mkdir /app
    COPY YOUR-APPLICATION.jar /app/YOUR-APPLICATION.jar
    COPY entrypoint.sh /entrypoint.sh
    RUN chmod +x /entrypoint.sh
    ENTRYPOINT ["/entrypoint.sh"]
    ```
3. You should also have a file called `entrypoint.sh` in the same directory as `Dockerfile`. The contents of `entrypoint.sh` should look like
    ```
    #!/bin/bash

    /jdk/bin/java -XX:+ExtendedDTraceProbes -XX:+PreserveFramePointer -XX:+StartAttachListener -XX:+UnlockDiagnosticVMOptions -XX:+DebugNonSafepoints -XX:-OmitStackTraceInFastThrow -XX:+ShowHiddenFrames --add-opens java.base/java.lang=ALL-UNNAMED  -XX:+TieredCompilation -jar /app/YOUR-APPLICATION.jar
    ```
4. Replace `YOUR-APPLICATION` in the above two file with the name of your `jar` file.
5. Build the Docker image
    ```
    docker build -t YOUR-DOCKER-REGISTRY/APPLICATION-IMAGE-NAME .
    ```
6. In a first terminal, run your application using Docker.
    ```
    docker run -d --name app --net host  YOUR-DOCKER-REGISTRY/APPLICATION-IMAGE-NAME
    ```
7. Continuously call a few endppoints of your application.
8. In a second terminal, run the following commands to generate stack traces and to run the tracer application `arvos-poc`.

    - Make sure the debugfs is mounted : 
        ```
        sudo mount -t debugfs debugfs /sys/kernel/debug
        ```
    - Run the tracer :
        ```
        export APP=app
        docker exec -it $APP /bin/bash -c "wget https://arthas.aliyun.com/arthas-boot.jar && java -jar arthas-boot.jar --attach-only --select YOUR-APPLICATION.jar" &&  docker run -it --rm -v  /sys/kernel/debug:/sys/kernel/debug:rw -v /lib/modules/$(uname -r):/lib/modules/$(uname -r) -v /usr/src:/usr/src --privileged --pid container:$APP ayoubensalem/arvos-poc $(docker exec -ti $APP pidof java)
        ``` 