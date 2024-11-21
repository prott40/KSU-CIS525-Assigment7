#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/queue.h>
#include <fcntl.h>
#include "inet.h"
#include "common.h"


int port;

// Structure to represent a connected client
struct client {
    int sock; // Socket descriptor
    char name[MAX]; // Client name
    LIST_ENTRY(client) clients; // List link
};

// Head of the list for storing connected clients
LIST_HEAD(client_list, client) client_list;

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

// Function to register the chat server with the Directory Server
void register_with_directory_server(const char *name) {
    int sock;
    struct sockaddr_in dir_addr;

    // Create a socket to connect to the Directory Server
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket for Directory Server");
        exit(EXIT_FAILURE);
    }

    // Set up the Directory Server address
    memset(&dir_addr, 0, sizeof(dir_addr));
    dir_addr.sin_family = AF_INET;
    dir_addr.sin_port = htons(SERV_HOST_ADDR);
    inet_pton(AF_INET, SERV_TCP_PORT, &dir_addr.sin_addr);

    // Connect to the Directory Server
    if (connect(sock, (struct sockaddr *)&dir_addr, sizeof(dir_addr)) < 0) {
        perror("Unable to connect to Directory Server");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Send the registration command
    write(sock, "REGISTER", strlen("REGISTER"));

    // Send the registration details (name and address)
    char buffer[MAX];
    snprintf(buffer, sizeof(buffer), "%s:%s:%d", name, SERV_TCP_PORT, port);
    write(sock, buffer, strlen(buffer));

    close(sock);
    printf("Registered with Directory Server as %s\n", name);
}

// Function to handle incoming client connections
void handle_new_connection(SSL_CTX *ctx, int server_sock) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
    if (client_sock < 0) {
        perror("Unable to accept new client connection");
        return;
    }

    // Establish SSL for the new client connection
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_sock);
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(client_sock);
        SSL_free(ssl);
        return;
    }

    // Add the new client to the client list
    struct client *new_client = malloc(sizeof(struct client));
    new_client->sock = client_sock;
    snprintf(new_client->name, sizeof(new_client->name), "Client%d", client_sock); // Assign a temporary name
    LIST_INSERT_HEAD(&client_list, new_client, clients);

    printf("New client connected: %s\n", new_client->name);

    // Notify the client of successful connection
    SSL_write(ssl, "Welcome to the chat server!\n", strlen("Welcome to the chat server!\n"));

    // Clean up SSL context
    SSL_free(ssl);
}

// Function to broadcast a message to all connected clients
void broadcast_message(const char *message) {
    struct client *client;
    LIST_FOREACH(client, &client_list, clients) {
        write(client->sock, message, strlen(message));
    }
}

// Function to handle client communication
void handle_client_communication(SSL_CTX *ctx, struct client *client) {
    char buffer[MAX];
    int bytes;

    // Establish SSL for the client
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client->sock);
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(client->sock);
        SSL_free(ssl);
        return;
    }

    // Read data from the client
    while ((bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes] = '\0';
        printf("%s: %s\n", client->name, buffer);

        // Broadcast the message to other clients
        broadcast_message(buffer);
    }

    // Clean up and remove the client
    printf("Client disconnected: %s\n", client->name);
    LIST_REMOVE(client, clients);
    close(client->sock);
    SSL_free(ssl);
    free(client);
}

int main(int argc, char **argv) {
    LIST_INIT(&client_list); // Initialize the client list
    if(argc >0){
		printf("starting  %s\n", argv[0]);
	}
	if(argc == 3){
        sscanf(argv[2],"%hu",&port);
	    if (port < 40000 || port > 65535) 
        {
		    printf("Invalid port number greater than 40000 and less than 65535\n");
		    exit(1);
	    }
		snprintf(s_out,MAX,"* %s %s",argv[1],argv[2]);
	}
    else{
        printf("Did not have all arguments not\n");
        printf("closing\n");
        exit(1);

    // Initialize OpenSSL and load the Chat Server certificate
    SSL_CTX *ctx = init_openssl("chatServer.crt", "chatServer.key");

    // Register the chat server with the Directory Server
    register_with_directory_server("KSU Football");

    // Create a TCP socket for the Chat Server
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Unable to create Chat Server socket");
        exit(EXIT_FAILURE);
    }

    // Bind the socket to a port
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind Chat Server socket");
        exit(EXIT_FAILURE);
    }

    // Start listening for incoming connections
    if (listen(server_sock, MAX_CLIENTS) < 0) {
        perror("Unable to listen on Chat Server socket");
        exit(EXIT_FAILURE);
    }

    printf("Chat Server listening on port %d...\n", port);

    while (1) {
        // Accept and handle new client connections
        handle_new_connection(ctx, server_sock);
    }

    // Clean up
    close(server_sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}
