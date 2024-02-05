# Edge Data Integrity(ICL-EDI)

C++ implementation of Inception &amp; Corruption Localization Scheme for Edge Data Integrity.

## Introduction

The given project is an implementation of a research paper titled "Efficient Verification of Edge Data Integrity in Edge Computing Environment." The paper addresses the challenge of verifying the integrity of edge data in distributed edge computing environments, where service vendors deploy their service instances and data on edge servers to serve users in close geographic proximity. Caching data on edge servers reduces latency for users but raises concerns about data corruption.

The authors propose a scheme named ICL-EDI (Inspection and Corruption Localization for Edge Data Integrity) to accurately and efficiently verify the integrity of edge data. ICL-EDI utilizes homomorphic tags to allow service vendors to verify multiple edge data replicas simultaneously. The scheme employs a sampling technique with a binary search to lower computational overhead for both service vendors and edge servers, making it practical for the resource-constrained edge computing environment.

ICL-EDI provides a novel approach to ensure data integrity in edge computing, allowing service vendors to inspect and localize corrupted edge data efficiently. The paper presents theoretical proofs and experimental results to demonstrate the effectiveness and efficiency of ICL-EDI.

## Requirements For Initial Setup

- Install C++ Compiler (GCC, Clang, or MSVC)
- Install Python (version 3.5 or higher)
- Install GNU Make or CMake (optional but recommended for building)
- Install [Botan](https://botan.randombit.net/)

## Setting Up

### 1. Clone/Download the Repository

### 2. Modify the server list in the servoce_vendor folder

It is written in the format edgeserver_name/edgeserver_ip/port. For example::(edge_server1/127.0.0.1/6001)

### 3. Change or create the edge servers accordingly

Create new edge servers as per the requirement and in each file put their port numbers in line 21.

### 4. Add the data

Add the testing data to data.txt file of each folder of edge server and service vendor.

### 5. Compile the files

Compile the files using the commands given at the header of each file.

### 6. Run the files

Run the service verndor followed by edge servers.

## Contributing

- [Ajay Vemuri]

## License

This project is licensed under the MIT License.

## Acknowledgments

We would like to express our gratitude to the open-source community and the developers behind GNU, Botan, and Python for providing the tools that made this project possible.
