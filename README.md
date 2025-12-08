# CECS-478-Section-1-Final-project-Christopher-Bermodes

Author: Christopher Bermodes

Purpose of the project:
Implementing a evident-tampering log in a simulated message network.

Important Notes
* This project was coded in C
* This project heavily utilized code and examples done in CECS 478 Lab 4 and Lab 5.
* The use of ChatGPT was used for research and for help in making code involving hash chaining, verification, Makefile creation and CI pipeline creation.
* Docker and Nano was used to code the project
* Instructions will be done with the assuption that the user is using:
  - Windows OS computer
  - Has Docker Desktop application installed in their system.
  - Have the CECS 478 class provide docker image files (CECS478_C_Docker_Bundle)
  - C (gcc) and Openssl is installed on the same docker images
  - The user has downloaded files directly from this directory
 
User Instructions:
1. Launch Docker deskstop application
2. Locate the CECS478_C_Docker_Bundle in user's file explorer
3. While in the CECS478_C_Docker_Bundle type "CMD" in the file pathway to open the folder in Command prompt
4. to build the docker image type:
   docker compose up -d
5. go to the docker attacker image by typing:
   docker exec -it cecs478c_attacker bash
6. With in the /app directory copy files in main branch to the directory.
7. Use OpenSSL to generate a certificate and private key for the server:
     openssl genrsa -out server.key 2048
     openssl req -new -x509 -key server.key -out server.crt -days 365

     During prompts, you will enter:
     Country Name: US
     State: California
     Locality: Long Beach
     Organization: CECS478
     Common Name: localhost
     Email: studentname@csulb.edu

8. Compile code from this repository by typing:
    * gcc -o server_tls server_test_build_1.0.c hash_logger_build_1.0.c -lssl -lcrypto
	* gcc -o client_tls client_test_build_1.0.c -lssl -lcrypto
	* gcc -o verify_log verify_log_build_1.0.c -lcrypto
   	* gcc -o read_logs read_logs_build_1.0.c -lcrypto

9. run server in command line on first terminal:
	* ./server_tls

10.run monitor on 2nd terminal:
	* tcpdump -i lo -w cecs478_final_project.pcap tcp port 4443

11. run client on 3rd terminal with user input message:
	* ./client_tls "put message here"

12. Check to see if tamper-evident log was created:
	* ls -l tamperlog.bin prev_hash.bin

13. Run verifier tool on any terminal (preferably on terminal that hosted the server):
	* ./verify_log tamperlog.bin

output should be something similar:
Verification complete: 6 entries verified.
Final chain head hash: 063da6014d81273047f6a9c49bd910fdc95eae631cb135f9440c4ffb6c31cf7c

14. Run insider program to simulate log being modified from a malicious person:
	* ./insider tamperlog.bin 4

15. To read the logs in human language:
	* ./read_logs tamperlog.bin

16. To "reset" the logs for a fresh run:
	* rm tamperlog.bin prev_hash.bin
