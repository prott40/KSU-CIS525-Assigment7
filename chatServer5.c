#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <errno.h>
#include "inet.h"
#include "common.h"

unsigned short int port;
int sockfd, nfds, activity;
struct sockaddr_in serv_addr, cli_addr;
fd_set readfds, writefds;
int usernum, gotgot;
// Structure to represent a connected client
struct client {
    int sock; // Socket descriptor
    SSL *ssl; // SSL connection
    char name[MAX]; // Client name
    char to[MAX], fr[MAX]; // message to the node and from the node
    char *tooptr, *friptr; // pointers for counting in message
    LIST_ENTRY(client) clients; // List link
};

// Head of the list for storing connected clients
LIST_HEAD(listhead, client) client_list;

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
    SSL_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    return ctx;
}

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

    //Error here 
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
    SSL_write(ssl, buffer, MAX);
    

    // Read response
    char response[MAX];
    int bytes = SSL_read(ssl, response, MAX);
    if (bytes > 0) {
        response[bytes] = '\0';
        printf("Directory Server response: %s\n", response);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
}

// sets the socket to non blocking
void set_nonblocking(int sock_fd) {
    int val = fcntl(sock_fd, F_GETFL, 0);
    fcntl(sock_fd, F_SETFL, val | O_NONBLOCK);
}

// initializes the buffers for that node
void initialize_client_buffers(struct client* cl) {
    cl->tooptr = cl->to;
    cl->friptr = cl->fr;
    snprintf(cl->name, MAX, "*");
}

int check_name(struct client *c, struct listhead *head)
{
    struct client * tt;
    LIST_FOREACH(tt, head, clients)
    {
        if(tt != c){
            if(strncmp(tt->name, c->name, MAX) == 0){
                return 1;
            }
        }
    }
    return 0;
}

void handle_new_connection(SSL_CTX *ctx, int sock_fd, struct listhead *head, int *Nfds) {
    // Create base messages
    char getuser[MAX] = "Enter your nickname:";
    char firstuser[MAX] = "You are the first user:\nEnter your nickname:";
    
    unsigned int clilen = sizeof(cli_addr);
    
    // Accept new connection
    int newsockfd = accept(sock_fd, (struct sockaddr *)&cli_addr, &clilen);
    if (newsockfd < 0) {
        perror("Accept error");
        return;
    }

    // Set to non-blocking
    

    // Create SSL for the new connection
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, newsockfd);

    // Perform SSL handshake
    int ssl_accept_result = SSL_accept(ssl);
    if (ssl_accept_result <= 0) {
        int ssl_err = SSL_get_error(ssl, ssl_accept_result);
        ERR_print_errors_fp(stderr);
        close(newsockfd);
        SSL_free(ssl);
        return;
    }

    // Create new client struct
    set_nonblocking(newsockfd);
    struct client *new_client = (struct client *)malloc(sizeof(struct client));
    new_client->sock = newsockfd;
    SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    new_client->ssl = ssl;
    initialize_client_buffers(new_client);
    LIST_INSERT_HEAD(head, new_client, clients);
    usernum++;

    if (newsockfd > *Nfds) {
        *Nfds = newsockfd; // set new max file descriptor
    }

    // Check if first user
    if(usernum == 1){
        snprintf(new_client->to, MAX, "%s", firstuser);
        new_client->tooptr = new_client->to;
    }

    else{
        snprintf(new_client->to, MAX, "%s", getuser);
        new_client->tooptr = new_client->to;
    }
}

// Rest of the code remains the same as in your original implementation, with these key changes:
int handle_client_message(struct client *cl, struct listhead *head) {
    int nread;
    char message_buffer[MAX + 1] = {0}; 

    // Set SSL socket to non-blocking mode
    SSL_set_mode(cl->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    // Read with a null-terminated buffer
    nread = SSL_read(cl->ssl, message_buffer, MAX);

    // Handle SSL read errors more gracefully
    if (nread < 0) {
        int ssl_err = SSL_get_error(cl->ssl, nread);
        
        // These errors typically mean "try again later" in non-blocking mode
        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
            return 0;  // Not an error, just not ready
        }

        char errbuf[256];
        // More serious errors
        if (ssl_err == SSL_ERROR_ZERO_RETURN) 
        {
           fprintf(ssl_err,"Zero Returned Error %s\n", errbuf);
            
        } 
        else 
        {
            // char errbuf[256];
            ERR_error_string_n(ssl_err, errbuf, sizeof(errbuf));
            fprintf(stderr, "SSL read error: %s\n", errbuf);
        }

         struct client* other;
            LIST_FOREACH(other, head, clients) 
            {       
                    snprintf(other->to, MAX, "%s:has disconnected", cl->name); //changed getter to other->name
                    other->tooptr = other->to;
            }

        // Cleanup for serious errors
        SSL_shutdown(cl->ssl);
        SSL_free(cl->ssl);
        close(cl->sock);
        LIST_REMOVE(cl, clients);
        free(cl);
        usernum--;
        
        return 1;
    }
    // Null-terminate the received message
    message_buffer[nread] = '\0';

    // Debug print of received message
    printf("Received message (length %d): '%s'\n", nread, message_buffer);

    // Explicitly check if this is the first message (nickname)
    if (cl->name[0] == '*') {
        // Trim whitespace and newline
        char *trimmed = message_buffer;
        while (*trimmed && (*trimmed == ' ' || *trimmed == '\n')) trimmed++;
        char *end = trimmed + strlen(trimmed) - 1;
        while (end > trimmed && (*end == ' ' || *end == '\n')) *end-- = '\0';

        printf("Attempting to register nickname: '%s'\n", trimmed);

        if (strnlen(trimmed, sizeof(trimmed)) == 0) {
            printf("Empty nickname, rejecting\n");
            
            SSL_shutdown(cl->ssl);
            SSL_free(cl->ssl);
            close(cl->sock);
            LIST_REMOVE(cl, clients);
            free(cl);
            usernum--;
            return 1;
        }
        snprintf(cl->name,"%s",trimmed);
        if (0 == check_name(cl, head)) {
            // Successfully registered nickname
            snprintf(cl->name, MAX, "%s", trimmed);
            printf("Nickname registered: %s\n", cl->name);
            

            // Send nickname acceptance message
            snprintf(cl->to, MAX, "Nickname %s accepted!", cl->name);
            struct client *other;
                LIST_FOREACH(other, head, clients) {
                        if (other != cl) {    
                            snprintf(other->to, MAX, "%s:has joined the chat", cl->name);
                            other->tooptr = other->to;  
                            write_to_client(cl);                          
                        } else  {
                            //snprintf(other->to, MAX, "%s:%s", cl->name, cl->fr);
                            //other->tooptr = other->to;
                        }
                }
                    
            
        } else {
            // Name already exists, disconnect client
            printf("Nickname %s already exists\n", trimmed);
             snprintf(cl->to, MAX, "nickname, rejecting", cl->name);
            cl->tooptr = cl->to;
            write_to_client(cl);
            SSL_shutdown(cl->ssl);
            SSL_free(cl->ssl);
            close(cl->sock);
            LIST_REMOVE(cl, clients);
            free(cl);
            usernum--;
            return 1;
        }
    } else {
        // Regular message handling
        
         printf("Received message (length %d): '%s'\n", nread, message_buffer);
            printf("Current client state - Name: %s, Socket: %d\n", cl->name, cl->sock);
        // Broadcast message to all other clients
        struct client *other;
        LIST_FOREACH(other, head, clients) {
            if (other != cl) {
                snprintf(other->to, MAX, "%s: %s", cl->name, message_buffer);
                printf("Broadcasting to client: %s\n", other->name);
                write_to_client(other);
            }
        }
    }

    return 0;
}



int write_to_client(struct client *cl, struct listhead * head) {
    int total_written = 0;
    int remaining = strnlen(cl->to,MAX);
    
    if (remaining == 0) {
        // No data to write
        return;
    }
    
    // Set SSL socket to non-blocking mode
    SSL_set_mode(cl->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    printf("Attempting to write to client: %s\n", cl->to);

    while (total_written < remaining) {
        int nwritten = SSL_write(cl->ssl, cl->to + total_written, remaining - total_written);
        
        if (nwritten < 0) {
            int ssl_err = SSL_get_error(cl->ssl, nwritten);
            
            // Handle SSL write errors
            if (ssl_err == SSL_ERROR_WANT_WRITE || ssl_err == SSL_ERROR_WANT_READ) {
                // Not ready to write, try again later
                printf("Write blocked, will retry\n");
                break;
            }
            struct client* other;
            LIST_FOREACH(other, head, clients) 
            {
                snprintf(other->to , MAX, "%s:has disconnected", cl->name); //changed getter to other->name
                other->tooptr = other->to;
            }
            // Serious error
            fprintf(stderr, "SSL write error: %d\n", ssl_err);
            SSL_shutdown(cl->ssl);
            SSL_free(cl->ssl);
            close(cl->sock);
            LIST_REMOVE(cl,clients);
            return 1;
        }
        
        total_written += nwritten;
        printf("Wrote %d bytes\n", total_written);
    }
    
    // Clear the buffer after writing
    memset(cl->to, 0, MAX);
    return 0;
}

int main(int argc, char **argv) {
    struct listhead new_client_list; // Declare the list correctly
    LIST_INIT(&new_client_list); // Initialize the client list
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
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Unable to create Chat Server socket\n");
        exit(EXIT_FAILURE);
    }

    // Bind the socket to a port
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind Chat Server socket");
        exit(EXIT_FAILURE);
    }
    int true = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&true, sizeof(true)) < 0) {
		perror("server: can't set stream socket address reuse option");
		exit(1);
	}
    // Register the chat server with the Directory Server
    register_with_directory_server(argv[1]);

    // Start listening for incoming connections
    if (listen(sockfd, MAX_CLIENTS) < 0) {
        perror("Unable to listen on Chat Server socket");
        exit(EXIT_FAILURE);
    }
    set_nonblocking(sockfd);
    printf("Chat Server listening on port %d...\n", port);

    while (1) {
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        FD_SET(sockfd, &readfds);
        nfds = sockfd;

        // Add client sockets to read and write sets
        struct client *cl;
        LIST_FOREACH(cl, &new_client_list, clients)  {
            FD_SET(cl->sock, &readfds);

            // Only set write if there's data to send
            if (strnlen(cl->to,MAX) > 0) { 
                FD_SET(cl->sock, &writefds);
            }
            if (cl->sock > nfds) {
                nfds = cl->sock;
            }
        }
        
        activity = select(nfds + 1, &readfds, &writefds, NULL, NULL);
        if (activity < 0 && errno != EINTR) {
            perror("Select error");
        }
        
        if (FD_ISSET(sockfd, &readfds)) {
            handle_new_connection(ctx, sockfd, &new_client_list, &nfds);
        }
        
        LIST_FOREACH(cl, &new_client_list, clients) {
            
            if (FD_ISSET(cl->sock, &readfds)) {
                SSL_accept(cl->ssl);
                if(handle_client_message(cl, &new_client_list) == 1){
                    continue;
                }
            }
            
            if (FD_ISSET(cl->sock, &writefds)) {
                SSL_connect(cl->ssl);
                write_to_client(cl,&new_client_list);
            }
           
        }
    }

    // Clean up
    close(sockfd);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}

