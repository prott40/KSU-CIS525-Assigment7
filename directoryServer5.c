#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/queue.h>
#include "inet.h"
#include "common.h"

// Structure to represent a registered chat server
struct chat_server {
    char name[MAX]; // Chat room name (e.g., "KSU Football")
    char address[MAX]; // Chat server address (IP:port)
    LIST_ENTRY(chat_server) servers; // List link
};

// Head of the list for storing registered chat servers
LIST_HEAD(chat_server_list, chat_server) server_list;

// Function to initialize OpenSSL
SSL_CTX *init_openssl(const char *cert_file, const char *key_file) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// Function to handle a chat server registration
void handle_registration(SSL *ssl) {
    char buffer[MAX];
    int bytes;

    // Read registration information from the chat server
    bytes = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes <= 0) {
        fprintf(stderr, "Error reading registration information.\n");
        return;
    }
    buffer[bytes] = '\0';

    // Parse the registration data (expected format: "name:address")
    char *name = strtok(buffer, ":");
    char *address = strtok(NULL, ":");
    if (!name || !address) {
        fprintf(stderr, "Invalid registration format.\n");
        return;
    }

    // Add the chat server to the list
    struct chat_server *new_server = malloc(sizeof(struct chat_server));
    snprintf(new_server->name, sizeof(new_server->name), "%s", name);
    snprintf(new_server->address, sizeof(new_server->address), "%s", address);
    LIST_INSERT_HEAD(&server_list, new_server, servers);

    printf("Registered chat server: %s (%s)\n", new_server->name, new_server->address);

    // Confirm the registration
    SSL_write(ssl, "Registration successful.\n", 25);
}

// Function to handle a client request for chat server list
void handle_client_request(SSL *ssl) {
    char buffer[MAX] = "";

    // Iterate through the list of registered servers and construct the response
    struct chat_server *server;
    LIST_FOREACH(server, &server_list, servers) {
        strncat(buffer, server->name, sizeof(buffer) - strlen(buffer) - 1);
        strncat(buffer, " - ", sizeof(buffer) - strlen(buffer) - 1);
        strncat(buffer, server->address, sizeof(buffer) - strlen(buffer) - 1);
        strncat(buffer, "\n", sizeof(buffer) - strlen(buffer) - 1);
    }

    // Send the response to the client
    SSL_write(ssl, buffer, strlen(buffer));
}

int main() {
    LIST_INIT(&server_list); // Initialize the server list

    // Initialize OpenSSL and load the Directory Server certificate
    SSL_CTX *ctx = init_openssl("directoryServer.crt", "directoryServer.key");

    // Create a TCP socket for the Directory Server
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    // Bind the socket to a port
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERV_TCP_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind socket");
        exit(EXIT_FAILURE);
    }

    // Start listening for incoming connections
    if (listen(sock, 5) < 0) {
        perror("Unable to listen on socket");
        exit(EXIT_FAILURE);
    }

    printf("Directory Server listening on port %d...\n", SERV_TCP_PORT);

    while (1) {
        // Accept a new connection
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0) {
            perror("Unable to accept connection");
            continue;
        }

        // Establish SSL for the new connection
        SSL *ssl = SSL_new(ctx);//
        SSL_set_fd(ssl, client_sock);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(client_sock);
            continue;
        }

        // Determine whether the connection is a registration or client request
        char buffer[MAX];
        int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            if (strcmp(buffer, "REGISTER") == 0) {
                handle_registration(ssl);
            } else if (strcmp(buffer, "GET_SERVERS") == 0) {
                handle_client_request(ssl);
            } else {
                fprintf(stderr, "Unknown command: %s\n", buffer);
            }
        }

        // Clean up the connection
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_sock);
    }

    // Clean up OpenSSL
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}
