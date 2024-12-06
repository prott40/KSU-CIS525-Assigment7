#include <stdio.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include "inet.h"
#include "common.h"


SSL_CTX *create_client_context() 
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    
    const char *cert_path = "./client.crt";
    const char *key_path = "./client.key";
    const char *ca_path = "./ca.crt";

    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error loading certificate from %s\n", cert_path);
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error loading private key from %s\n", key_path);
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        exit(1);
    }

    // Load CA certificate for verification
    SSL_CTX_load_verify_locations(ctx, ca_path, NULL);

    return ctx;
}

int connect_to_directory_server(SSL_CTX *ctx) {
    int sockfd;
    struct sockaddr_in dir_addr;
    //char s_in[MAX] = {'\0'};
    char list[500] = {'\0'};

    // Set up directory server address
    memset((char *) &dir_addr, 0, sizeof(dir_addr));
    dir_addr.sin_family = AF_INET;
    dir_addr.sin_addr.s_addr = inet_addr(SERV_HOST_ADDR);
    dir_addr.sin_port = htons(SERV_TCP_PORT);

    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("client: can't open stream socket");
        return -1;
    }
    
    // Connect to directory server
    if (connect(sockfd, (struct sockaddr *) &dir_addr, sizeof(dir_addr)) < 0) {
        perror("client: can't connect to server");
        close(sockfd);
        return -1;
    }

    // Establish SSL connection
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sockfd);
        return -1;
    }

    // Request server list
    SSL_write(ssl, "&", MAX);

    // Read server list
    int bytes = SSL_read(ssl, list, sizeof(list) - 1);
    if (bytes > 0) 
    {
        list[bytes] = '\0'; // Null-terminate the received string


        printf("Available Chat Servers:\n%s\n",list);
    } else {
        fprintf(stderr, "Failed to retrieve server list.\n");
        ERR_print_errors_fp(stderr);
    }

    // Keep the SSL connection open for further interactions if needed
    return sockfd;
}

int connect_to_chat_server(SSL *ssl, const char *chataddy, unsigned short chatport) {
    int sersockfd;
    struct sockaddr_in serv_addr;
    

    // Create socket
    if ((sersockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("client: can't open stream socket");
        return -1;
    }

    // Set up chat server address
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(chataddy);
    serv_addr.sin_port = htons(chatport);

    // Connect to chat server
    if (connect(sersockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("client: can't connect to chat server");
        close(sersockfd);
        return -1;
    }

    // Establish SSL connection
    
    if (!ssl) {
        fprintf(stderr, "SSL_new failed.\n");
        close(sersockfd);
        return -1;
    }

    SSL_set_fd(ssl, sersockfd);
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "SSL_connect failed:\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sersockfd);
        return -1;
    }

    // Welcome message
    char welcome[MAX];
    int welcome_len = SSL_read(ssl, welcome, sizeof(welcome) - 1);
    if (welcome_len > 0) {
        welcome[welcome_len] = '\0';
        printf("%s\n", welcome);
    } else {
        fprintf(stderr, "SSL_read failed:\n");
        ERR_print_errors_fp(stderr);
    }

    return sersockfd;
}

int main() {
    SSL_CTX *ctx;
    char chataddy[IP_LEN] = {'\0'};
    short unsigned int chatport;
    bool linked = false;

    // Initialize SSL
    ctx = create_client_context();

    // Connect to directory server and get server list
    int dirfd = connect_to_directory_server(ctx);
    if (dirfd < 0) {
        fprintf(stderr, "Failed to connect to directory server\n");
        SSL_CTX_free(ctx);
        return 1;
    }

    // Prompt for chat server selection
    printf("Enter server to connect to in the format: <Port> <Host IP> (Ex: 44332 129.130.10.39)\n");
    while (!linked) {
        if (scanf("%hu %s", &chatport, chataddy) != 2) {
            printf("Invalid entry, please reenter\n");
            // Clear input buffer
            while (getchar() != '\n');
            continue;
        }

        // Validate chataddy
        if (inet_addr(chataddy) == INADDR_NONE) {
            printf("Invalid IP address, please reenter\n");
            continue;
        } 
        else if(chatport <= 0 || chatport > 65534) {
            printf("Invalid port number\n");
            continue;
        }
        else {
            linked = true;
        }
    }

    // Connect to selected chat server
    SSL *ssl = SSL_new(ctx);
    int sersockfd = connect_to_chat_server(ssl, chataddy, chatport);
    if (sersockfd < 0) {
        fprintf(stderr, "Failed to connect to chat server\n");
        SSL_CTX_free(ctx);
        return 1;
    }

    // Chat loop
    fd_set readset;
    char s_out[MAX] = {'\0'};
    char s_in[MAX] = {'\0'};
    
    
    fcntl(sersockfd, F_SETFL, O_NONBLOCK);
    

   for (;;) {
        FD_ZERO(&readset);
        FD_SET(STDIN_FILENO, &readset);
        FD_SET(sersockfd, &readset);
        
        memset(s_out, 0, sizeof(s_out));
        memset(s_in, 0, sizeof(s_in));

        if (select(sersockfd + 1, &readset, NULL, NULL, NULL) > 0) {
            // Check user input
            if (FD_ISSET(STDIN_FILENO, &readset)) {
                 int ssl_connect_result = SSL_connect(ssl);
                    if(ssl_connect_result < 0){
                        printf("SSL Handshake failedy\n");
                    }
                if (scanf(" %[^\n]",s_out) == 1) {
                    s_out[strcspn(s_out, "\n")] = '\0';
                    
                    int write_result = SSL_write(ssl, s_out, MAX);

                if (write_result <= 0) {
                    int ssl_err = SSL_get_error(ssl, write_result);
                    
                    switch (ssl_err) {
                        case SSL_ERROR_WANT_WRITE:
                            printf("SSL connection not ready to write. Retrying...\n");
                            break;
                        case SSL_ERROR_WANT_READ:
                            printf("SSL needs to read before writing\n");
                            break;
                        case SSL_ERROR_ZERO_RETURN:
                            printf("SSL connection closed\n");
                            break;
                        case SSL_ERROR_SYSCALL:
                            perror("SSL write error (syscall)");
                            break;
                        default:
                            fprintf(stderr, "Unexpected SSL write error: %d\n", ssl_err);
                            break;
                    }
                }
                }
            }

            // Check server messages
            if (FD_ISSET(sersockfd, &readset)) {
                int ssl_connect_result = SSL_accept(ssl);
                    if(ssl_connect_result < 0){
                        printf("SSL Handshake failedy\n");
                    }
                int bytes = SSL_read(ssl, s_in, sizeof(s_in) - 1);
                if (bytes <= 0) {
                    printf("Server has shut down\n");
                    break;
                } else {
                    s_in[bytes] = '\0';
                    printf("%s\n", s_in);
                }
            }
        }
    }

    // Cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sersockfd);
    SSL_CTX_free(ctx);

    return 0;
}