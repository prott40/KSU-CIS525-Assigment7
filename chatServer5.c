#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/queue.h>
#include <fcntl.h>
#include "inet.h"//
#include "common.h"


unsigned short int port;
fd_set readfds, serfds;

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
    if (!cert_file || !*cert_file) {
        fprintf(stderr, "Error: Certificate file path is NULL or empty\n");
        return NULL;
    }
    if (!key_file || !*key_file) {
        fprintf(stderr, "Error: Key file path is NULL or empty\n");
        return NULL;
    }

    if (access(cert_file, R_OK) != 0) {
        perror("Error: Cannot access certificate file");
        return NULL;
    }
    if (access(key_file, R_OK) != 0) {
        perror("Error: Cannot access key file");
        return NULL;
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Failed to load certificate file: %s\n", cert_file);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Failed to load key file: %s\n", key_file);
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

//Bug might be here possibly
// Function to register the chat server with the Directory Server
void register_with_directory_server(const char *name) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket for Directory Server");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in dir_addr = {0};
    dir_addr.sin_family = AF_INET;
    dir_addr.sin_port = htons(SERV_TCP_PORT);
    
    if (inet_pton(AF_INET, SERV_HOST_ADDR, &dir_addr.sin_addr) <= 0) {
        perror("inet_pton failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr *)&dir_addr, sizeof(dir_addr)) < 0) {
        perror("Unable to connect to Directory Server");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Establish SSL connection
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Send registration command
    SSL_write(ssl, "*", MAX);

    // Send server details
    char buffer[MAX];
    snprintf(buffer, MAX, "%s:%d", name, port);
    SSL_write(ssl, buffer, strlen(buffer));

    // Read response
    char response[MAX];
    int bytes = SSL_read(ssl, response, sizeof(response) - 1);
    if (bytes > 0) {
        response[bytes] = '\0';
        printf("Directory Server response: %s\n", response);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
}

// Function to handle incoming client connections
// BUG POSSIBLY OCCURING HERE BECAUSE SERVER IS NOT ACCEPTING VIA SSL TO DIRECTORY
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

    if (SSL_accept(ssl) <= 0) 
    {
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
    while ((bytes = SSL_read(ssl, buffer, MAX)) > 0) {
       char outmes[MAX];
        snprintf(outmes, MAX,"%s: %s", client->name, buffer);

        // Broadcast the message to other clients
        broadcast_message(outmes);
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
    char s_out[MAX];
    if(argc >0){
		printf("starting  %s\n", argv[0]);
	}
	if(argc == 3){
        if(0 < sscanf(argv[2],"%hu",&port))
        {
            if (port < 40000 || port > 65535) 
            {
                printf("Invalid port number greater than 40000 and less than 65535\n");
                exit(1);
            }
		snprintf(s_out,MAX,"* %s %s",argv[1],argv[2]);
        printf("all args and correct port\n");
        }
	   
	}
    else{
        printf("Did not have all arguments not\n");
        printf("closing\n");
        exit(1);
    }

    // Initialize OpenSSL and load the Chat Server certificate
    char crt[MAX];
    char key[MAX];
    snprintf(crt,MAX,"%s.crt",argv[1]);
    snprintf(key,MAX,"%s.key",argv[1]);
    printf("Certificate file: %s\n", crt);
    printf("Key file: %s\n", key);

    SSL_CTX *ctx = init_openssl(crt, key);

    if (ctx == NULL) {
        printf("Failed to initialize OpenSSL context\n");
        exit(1);
    }
    
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

    // Register the chat server with the Directory Server
    register_with_directory_server(argv[1]);

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

