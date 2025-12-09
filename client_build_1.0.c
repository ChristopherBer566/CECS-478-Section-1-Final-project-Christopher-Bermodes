#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 4443
#define MAX_BUFFER 1024
#define SERVER_IP "127.0.0.1"

void error_exit(const char *msg) {
	perror(msg);
	exit(EXIT_FAILURE);
}

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

static SSL_CTX* create_client_context(void) {
	const SSL_METHOD* method = TLS_client_method();
	SSL_CTX* ctx = SSL_CTX_new(method);
	if(!ctx) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	return ctx;
}
int main(int argc, char *argv[]) {
        if (argc < 2) {
                fprintf(stderr, "Usage: %s \"message to send\"\n", argv[0]);
                return EXIT_FAILURE;
        }

        const char *user_msg = argv[1];
        int client_fd;
        struct sockaddr_in serv_addr;
        char buffer[MAX_BUFFER] = {0};
        const char *check_in_message = "Client 'tester': Entering server, requesting clearance.\n";

        printf("--- CECS 478 Final Project (TLS + Tamper evident logs) ---\n");

	// Initializing Openssl
	init_openssl();
	SSL_CTX* ctx = create_client_context();

	// creating the socket
	if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		error_exit("Establishing Socket failed");
	}
	printf("1. Socket has been created. \n");

	// Configuring the target address
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);

	//Convert the server's IP form text to network format
	if(inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
		error_exit("Invalid IP was provided, please check code");
	}
	printf("Targeting Server at IP: %s on Port: %d \n", SERVER_IP, PORT);

	//connecting to the server.
	if(connect(client_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		error_exit("connection failed. Is the server listening?");
	}
	printf("2. Connnection established with the Server\n");

	//creating SSL object and set socket
	SSL* ssl = SSL_new(ctx);
	SSL_set_fd(ssl, client_fd);

	if (SSL_connect(ssl) <= 0) {
		ERR_print_errors_fp(stderr);
		SSL_free(ssl);
		close(client_fd);
		SSL_CTX_free(ctx);
		cleanup_openssl();
		return 1;
	}
	printf("secure TLS communication link established with the server\n");

	// Sending check in message
        SSL_write(ssl, check_in_message, (int)strlen(check_in_message));
        printf("Check-in message sent : \"%s\"\n", check_in_message);
        printf("\n");

	// Sending user input to server
        SSL_write(ssl, user_msg, (int)strlen(user_msg));
        printf("Message sent: \"%s\"\n", user_msg);

        shutdown(client_fd, SHUT_WR);

	for (int i = 0; i < 2; ++i) {
		memset(buffer, 0, MAX_BUFFER);
		ssize_t valread = SSL_read(ssl, buffer, MAX_BUFFER -1);
		if (valread <= 0) {
			printf("Server link severed unexpectedly while waiting for reply %d.\n", i + 1);
			break;
		}
		buffer[valread] = '\0';
		printf("4.%d Acknowledgment received: \"%s\"\n", i + 1, buffer);
	}

	// secure the communication Link
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
        SSL_CTX_free(ctx);
        cleanup_openssl();

        printf("Server communication link secured. Mission complete.\n");
	return 0;
}
