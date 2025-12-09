# CECS-478-Section-1-Final-project-Christopher-Bermodes

Author: Christopher Bermodes

Purpose of the project:
Implementing a evident-tampering log in a simulated message network.

Important Notes
* This project was coded in C
* This project heavily utilized code and examples done in CECS 478 Lab 4 and Lab 5.
* The use of ChatGPT was used for research and for help in making code involving hash chaining, verification, Makefile creation and CI pipeline creation.
* DISCLAIMER: Makefile and CI pipeline where done ENTIRELY with ChatGPT. At the current version Makefile does work and can perform demos and tests. However, it is HIGHLY recommended to do commands manually for clarity and readability.
* ALPHA and BETA tests were conducted both manually using Makefile and manually. CI pipeline WAS NOT USED for testing.
* Docker and Nano was used to code the project
* Instructions will be done with the assuption that the user is using:
  - Windows OS computer
  - Has Docker Desktop application installed in their system.
  - Have the CECS 478 class provide docker image files (CECS478_C_Docker_Bundle)
  - C (gcc) and Openssl is installed on the same docker images
  - The user has downloaded files directly from this directory
 
File structure:
* client_build_1.0.c          → TLS client
* server_build_1.0.c          → TLS server
* hash_logger_build_1.0.c/.h  → Hash-chained logging
* verify_log_build_1.0.c      → Hash chain verifier
* read_logs_build_1.0.c       → Binary log viewer
* insider_build_1.0.c         → Malicious log tampering tool
* server.crt / server.key     → TLS certificate & key
* test_hash_logger.c / test_verify_log.c        → offline tools that assists with ALPHA and BETA testing
 
User Instructions are provided in RUNBOOK file.
