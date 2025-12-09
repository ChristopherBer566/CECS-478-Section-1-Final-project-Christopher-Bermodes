#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "hash_logger_build_1.0.h"

#define PORT 4443
#define MAX_BUFFER 1024
#define BACKLOG 5

#define CERT_FILE "server.crt"
#define KEY_FILE "server.key"

// Function to handle critical errors and shut down operations
void error_exit(const char* msg) {
	perror(msg);
	exit(EXIT_FAILURE);
}

// Adding functions for openssl
void init_openssl(void) {
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl(void) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    OPENSSL_cleanup();
#else
    EVP_cleanup();
#endif
}

static SSL_CTX* create_server_context(void) {
	const SSL_METHOD* method = TLS_server_method();
	SSL_CTX* ctx = SSL_CTX_new(method);
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	return ctx;
}

void configure_context(SSL_CTX* ctx) {
	if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
}


int main(void) {
	int server_fd, new_socket;
	struct sockaddr_in address;
	int addrlen = sizeof(address);
	char buffer[MAX_BUFFER] = { 0 };
	const char* confirmation = "Watchtower: Roger, message received and acknowledged.\n";


	// Initializing OpenSSL
	init_openssl();
	SSL_CTX* ctx = create_server_context();
	configure_context(ctx);

	// Updateing the name of server
	printf("--- Long Beach Harbor final project Server (TLS + Tamper-Evident Logs) ---\n");

	// 1. Install the Radio Gear (Create the socket)
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
		error_exit("socket Failed");
	}
	printf("1. Server Socket initialized.\n");

	// Configure the Tower's channel and location
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY; // Listen on all network radios
	address.sin_port = htons(PORT); // Assign our designated Channel 4443

	// 2. Assign a Designated Channel (Bind the socket)
		if (bind(server_fd, (struct sockaddr*)&address, addrlen) < 0) {
			error_exit("Channel assignment failed");
		}
	printf("2. Channel %d assigned and secured.\n", PORT);

	// 3. Listen for incoming calls
	if (listen(server_fd, BACKLOG) < 0) {
		error_exit("Listening failed");
	}
	printf("3. Server is listening for Clients...\n");

	// 4. Route the Incoming Call (Accept a connection)
	if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
		error_exit("Call acceptance failed");
	}
	printf("4. New Client connection established.\n");

	// Identify the calling clients IP and logging it
	char client_ip[INET_ADDRSTRLEN];
	const char *ip_str = inet_ntoa(address.sin_addr);
	strncpy(client_ip, ip_str, INET_ADDRSTRLEN);
	client_ip[INET_ADDRSTRLEN - 1] = '\0';

	printf(" Client Location ID (IP): %s\n", inet_ntoa(address.sin_addr));

	// Tamper-evident log: recording connection event
	append_log_entry(client_ip, "CONNECT");

	// Creating the ssl obj and set socket
	SSL* ssl = SSL_new(ctx);
	SSL_set_fd(ssl, new_socket);

	if (SSL_accept(ssl) <= 0) {
		ERR_print_errors_fp(stderr);
		close(new_socket);
		close(server_fd);
		SSL_CTX_free(ctx);
		cleanup_openssl();
		return 1;
	}
	printf("5. TLS handshake completed with client.\n");
	append_log_entry(client_ip, "TLS_HANDSHAKE_OK");

	printf("6. Awaiting messages from the client. . .\n");


	// 5. Handle the Traffic (Receive message)
	while (1) {
		memset(buffer, 0, MAX_BUFFER);
		int valread = SSL_read(ssl, buffer, MAX_BUFFER -1);
		if (valread <= 0) {
			printf(" Client finished sending or connection closed (valread=%d).\n", valread);
			break;
		}
		buffer[valread] = '\0';

		printf("--- Received (%d bytes): \"%s\"\n", valread, buffer);

		// logging the received date in  tamper-evident log
		append_log_entry(client_ip, buffer);
	}

	printf("\n");

	// Send an official confirmation back
	SSL_write(ssl, confirmation, (int)strlen(confirmation));
	printf("7. Official confirmation sent back to client.\n");
	printf("\n");
	//recording confirmation sent to client
	append_log_entry(client_ip, "SENT: confirmation");

	// recording closed connection to client
	append_log_entry(client_ip, "DISCONNECT");

	// 7. Secure all communication links
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(new_socket);
	close(server_fd);
	SSL_CTX_free(ctx);
	cleanup_openssl();


	printf("8. Communication links secured. Server standing down.\n");
	return 0;
}
