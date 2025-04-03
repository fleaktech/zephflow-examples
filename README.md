# Cisco ASA to OCSF Transformation with ZephFlow

This repository contains example code demonstrating how to use ZephFlow to process Cisco ASA firewall logs and transform
them into the Open Cybersecurity Schema Framework (OCSF) format.

## Overview

The example shows how to build a data processing pipeline that:

- Reads Cisco ASA log messages from a file
- Parses the syslog header format
- Extracts message-specific information using Grok patterns
- Transforms the data into standardized OCSF format
- Outputs the results as JSON

## Tutorial

For a detailed explanation of how this code works, please refer to the tutorial:

[Standardizing Cisco ASA Logs to OCSF with ZephFlow](https://docs.fleak.ai/zephflow/tutorials/standardize_ciscoasa_to_ocsf)

## Prerequisites

- Java 21 or higher
- Gradle or Maven for dependency management
- GitHub access token with `read:packages` permission

## Running the Example

1. Configure your build tool to use GitHub Packages (see the tutorial for details)
2. Run the example using your IDE or build tool

## License

This example code is licensed under the Apache License 2.0.