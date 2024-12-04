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
struct chat_server 
{
    char name[MAX]; // Chat room name (e.g., "KSU Football")
    int address; // Chat server address (IP:port)
    LIST_ENTRY(chat_server) servers; // List link
};

// Head of the list for storing registered chat servers
LIST_HEAD(chat_server_list, chat_server) server_list;

// Function to initialize OpenSSL
SSL_CTX *init_openssl(const char *cert_file, const char *key_file) 
{
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


int setup_server_socket(int port, const char *host_addr) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        return -1;
    }

    // Set socket to non-blocking mode
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(host_addr);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind socket");
        close(sock);
        return -1;
    }

    if (listen(sock, 10) < 0) {
        perror("Unable to listen on socket");
        close(sock);
        return -1;
    }

    return sock;
}

//Fix later
void handle_client_request(SSL *ssl) {
    char buffer[MAX] = "";
    struct chat_server *server;
    LIST_FOREACH(server, &server_list, servers) {
        snprintf(buffer, MAX, "%s-%d",
                 server->name, 
                 server->address);
                 SSL_write(ssl, buffer, MAX);
    }
    snprintf(buffer,MAX, "&");
    SSL_write(ssl,buffer,MAX);// signifies end on list
    
}


//handles registrations with 
void handle_registration(SSL *ssl) {
    char buffer[MAX];
    int bytes = SSL_read(ssl, buffer, MAX);
    if (bytes <= 0) {
        fprintf(stderr, "Error reading registration information.\n");
        return;
    }
    
    buffer[bytes] = '\0';
    char name[40];
    int address;
    if (sscanf(buffer, "%49[^:]:%d", name, &address) == 2) {
    printf("name = '%s', address = %d\n", name, address);
    } 
    else {
        printf("Parsing failed!\n");
    }
   
    if (!name || !address) {
        fprintf(stderr, "Invalid registration format.\n");
        SSL_write(ssl, "Registration failed.\n", MAX);
        return;
    }

    struct chat_server *new_server = malloc(sizeof(struct chat_server));
    
    new_server->address = address;
    snprintf(new_server->name, MAX, "%s", name);
    //snprintf(new_server->address, MAX, "%d", address);
    LIST_INSERT_HEAD(&server_list, new_server, servers);

    printf("Registered chat server: %s (%d)\n", new_server->name, new_server->address);
    SSL_write(ssl, "Registration successful.\n", 25);
}

int main() {
    LIST_INIT(&server_list);

    SSL_CTX *ctx = init_openssl("directoryServer.crt", "directoryServer.key");
    if (!ctx) {
        fprintf(stderr, "Failed to initialize SSL context\n");
        exit(EXIT_FAILURE);
    }

    int server_sock = setup_server_socket(SERV_TCP_PORT, SERV_HOST_ADDR);
    if (server_sock < 0) {
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    fd_set master_set, read_set;
    FD_ZERO(&master_set);
    FD_SET(server_sock, &master_set);
    int max_fd = server_sock;

    printf("Directory Server listening on port %d...\n", SERV_TCP_PORT);

    while (1) {
        read_set = master_set;
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int activity = select(max_fd + 1, &read_set, NULL, NULL, &timeout);
        if (activity < 0 && errno != EINTR) {
            perror("select error");
            break;
        }

        if (FD_ISSET(server_sock, &read_set)) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);

            if (client_sock < 0) {
                if (errno != EWOULDBLOCK) {
                    perror("accept error");
                }
                continue;
            }

            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, client_sock);

            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                SSL_free(ssl);
                close(client_sock);
                continue;
            }

            // Read initial command
            char buffer[MAX];
            int bytes = SSL_read(ssl, buffer, MAX);
            if (bytes > 0) {
                buffer[bytes] = '\0';
                if (buffer[0] == '*') {
                    handle_registration(ssl);
                } else if (buffer[0] == '&'){
                    handle_client_request(ssl);
                } else {
                    fprintf(stderr, "Unknown command: %s\n", buffer);
                }
            }

            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_sock);
        }
    }

    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
