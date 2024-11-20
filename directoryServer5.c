#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <string.h>
#include <arpa/inet.h>

#define MAX 1024
#define MAX_CLIENTS 10
#define SERV_TCP_PORT 12345
#define IP_LEN 16

// Enum for connection types
typedef enum {
    CLIENT,
    SERVER
} connection_type;

// Struct to represent each connection (client or server)
struct entry {
    SSL *ssl;               // SSL object for secure connection
    int filedesc;           // Socket file descriptor
    char topic[MAX];        // Chat topic (if server connection)
    char ip[IP_LEN];        // Client IP address
    int port;               // Port for the chat server (if server connection)
    connection_type type;   // Type: CLIENT or SERVER
    struct entry *next;     // Linked list next pointer
};

// Head of the linked list
struct entry *head = NULL;

// Linked list management functions
void add_connection(struct entry *new_entry) {
    new_entry->next = head;
    head = new_entry;
}

void remove_connection(struct entry *conn) {
    struct entry *temp = head;
    struct entry *prev = NULL;
    while (temp != NULL) {
        if (temp == conn) {
            if (prev == NULL) {
                head = temp->next;  // Remove from head
            } else {
                prev->next = temp->next;  // Remove from list
            }
            free(temp);
            return;
        }
        prev = temp;
        temp = temp->next;
    }
}

SSL_CTX *create_server_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (SSL_CTX_use_certificate_file(ctx, "directoryServer.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "directoryServer.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        exit(1);
    }
    if (SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    return ctx;
}

void handle_client(SSL *ssl, struct entry *client_entry) {
    char buffer[MAX];
    int bytes = SSL_read(ssl, buffer, MAX);
    if (bytes < 0) {
        perror("Read error");
        return;
    } else if (bytes == 0) {
        printf("Client disconnected\n");
        close(SSL_get_fd(ssl));
        return;
    }

    buffer[bytes] = '\0';
    printf("Received message from client: %s\n", buffer);

    if (buffer[0] == '*') {
        // Extract topic and port
        char topic[MAX];
        int port;
        int result = sscanf(buffer, "* %s %d", topic, &port);
        if (result == 2) {
            printf("Successfully read topic: %s and port: %d\n", topic, port);
        } else {
            printf("Failed to read topic and port\n");
            return;
        }

        // Check if the topic is already in the list of servers
        struct entry *server = head;
        while (server) {
            if (server->type == SERVER && strncmp(server->topic, topic, MAX) == 0) {
                snprintf(buffer, MAX, "Connecting to server: %s", topic);
                SSL_write(ssl, buffer, strlen(buffer));
                break;
            }
            server = server->next;
        }
    }
}

void handle_select(int sockfd, SSL_CTX *ctx) {
    fd_set readfds;
    int nfds = sockfd;
    struct entry *conn;
    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);

    // Add SSL sockets (clients and servers) to the select set
    struct entry *current = head;
    while (current) {
        FD_SET(current->filedesc, &readfds);
        if (current->filedesc > nfds) nfds = current->filedesc;
        current = current->next;
    }

    int activity = select(nfds + 1, &readfds, NULL, NULL, NULL);
    if (activity < 0) {
        perror("Select error");
        return;
    }

    // Check for new client connections on the server socket
    if (FD_ISSET(sockfd, &readfds)) {
        struct sockaddr_in cli_addr;
        socklen_t clilen = sizeof(cli_addr);
        int newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
        if (newsockfd < 0) {
            perror("Accept error");
            return;
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, newsockfd);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(newsockfd);
            return;
        }

        struct entry *new_entry = (struct entry *)malloc(sizeof(struct entry));
        new_entry->ssl = ssl;
        new_entry->filedesc = newsockfd;
        new_entry->type = CLIENT;  // This is a client connection
        add_connection(new_entry);

        printf("New client connected\n");
    }

    // Handle communication with clients and servers
    current = head;
    while (current) {
        if (FD_ISSET(current->filedesc, &readfds)) {
            if (current->type == CLIENT) {
                // Handle client communication
                handle_client(current->ssl, current);
            }
            // Optionally handle server communication here
        }
        current = current->next;
    }
}

int main() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ctx = create_server_context();
    int sockfd;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Server: can't open stream socket");
        exit(1);
    }

    int true = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&true, sizeof(true)) < 0) {
        perror("Server: can't set socket reuse address");
        exit(1);
    }

    struct sockaddr_in serv_addr;
    memset((char *)&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(SERV_TCP_PORT);

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Server: can't bind address");
        exit(1);
    }

    listen(sockfd, MAX_CLIENTS);

    // Main loop
    while (1) {
        handle_select(sockfd, ctx);
    }

    // Cleanup
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}

/*
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/queue.h>
#include "inet.h"
#include "common.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>


#define IP_LEN 16
struct entry{
	int filedesc;
	int port;
	char topic[MAX];
	char ip[IP_LEN];
	
	LIST_ENTRY(entry) entries;
};

LIST_HEAD(listhead,entry);

SSL_CTX *create_directory_server_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    
    // Load Directory Server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "dir_server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, "dir_server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(1);
    }

    return ctx;
}

void verify_directory_server_certificate(SSL *ssl) {
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL) {
        printf("No certificate presented by the Directory Server\n");
        exit(1);
    }

    X509_NAME *subject_name = X509_get_subject_name(cert);
    char cn[256];
    X509_NAME_get_text_by_NID(subject_name, NID_commonName, cn, sizeof(cn));
    
    if (strcmp(cn, "Directory Server") != 0) {
        printf("Certificate CN mismatch. Expected 'Directory Server', but got '%s'\n", cn);
        exit(1);
    }

    X509_free(cert);
}

void *handle_client(void *arg) {
    SSL *ssl = (SSL *)arg;
    char buffer[1024];
    
    // Perform SSL handshake
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    
    // After handshake, retrieve client certificate and validate it
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL) {
        printf("No client certificate presented\n");
    } else {
        X509_NAME *subject_name = X509_get_subject_name(cert);
        char cn[256];
        X509_NAME_get_text_by_NID(subject_name, NID_commonName, cn, sizeof(cn));
        printf("Client certificate CN: %s\n", cn);
        X509_free(cert);
    }

    // Determine the chat room (could be sent as part of the client request)
    SSL_read(ssl, buffer, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';  // Null terminate the string
    printf("Client wants to join: %s\n", buffer);

    // After client authentication, hand off to the appropriate chat server
    // In a real-world scenario, here we would initiate a connection to the chat server
    int chat_server_fd = connect_to_chat_server(buffer);  // Example function to connect to the chat server
    if (chat_server_fd < 0) {
        printf("Failed to connect to chat server for room %s\n", buffer);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return NULL;
    }

    // Now, pass the SSL object to the chat server to continue communication
    SSL *chat_ssl = SSL_new(ctx);  // Use the same context (or create a new one)
    SSL_set_fd(chat_ssl, chat_server_fd);
    SSL_accept(chat_ssl);  // Perform the SSL handshake with the chat server

    // Optionally, communicate with the chat server (pass messages back and forth)

    // Free the client connection after handing off to the chat server
    SSL_shutdown(ssl);
    SSL_free(ssl);

    // Continue communicating with the chat server
    communicate_with_chat_server(chat_ssl);

    // Clean up after chat server interaction
    SSL_shutdown(chat_ssl);
    SSL_free(chat_ssl);
    close(chat_server_fd);
    
    return NULL;
}

int connect_to_chat_server(const char *chat_room) {
    // Connect to the appropriate chat server based on the chat room name
    int chat_server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (chat_server_fd < 0) {
        perror("Unable to create socket for chat server");
        return -1;
    }

    struct sockaddr_in chat_addr;
    chat_addr.sin_family = AF_INET;
    chat_addr.sin_port = htons(12346); // Assuming chat servers are running on port 12346
    chat_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Assuming the chat server is on localhost

    if (connect(chat_server_fd, (struct sockaddr *)&chat_addr, sizeof(chat_addr)) < 0) {
        perror("Unable to connect to chat server");
        close(chat_server_fd);
        return -1;
    }

    return chat_server_fd;
}

int main(int argc, char **argv)
{
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	int				sockfd, newsockfd;
	unsigned int	clilen;
	struct sockaddr_in cli_addr, serv_addr;
	char				s_in[MAX]= {'\0'};
	char				s_out[MAX]= {'\0'};
	char                list[500] = {'\0'};
	//char 				nullifier[MAX] ={'\0'};
	
	struct entry * check;
	struct entry * con;
	//char name[MAX];
	//int port;
	//int ip;
	fd_set readfds;
	//struct HEADNAME *headptr;
	struct listhead head;
	int nfds;
//
	LIST_INIT(&head);
	//int clientsock;

	/* Create communication endpoint */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("server: can't open stream socket");
		exit(1);
	}

	/* Add SO_REAUSEADDR option to prevent address in use errors (modified from: "Hands-On Network
	* Programming with C" Van Winkle, 2019. https://learning.oreilly.com/library/view/hands-on-network-programming/9781789349863/5130fe1b-5c8c-42c0-8656-4990bb7baf2e.xhtml */
	int true = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&true, sizeof(true)) < 0) {
		perror("server: can't set stream socket address reuse option");
		exit(1);
	}

	/* Bind socket to local address */
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family		= AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port		= htons(SERV_TCP_PORT);

	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("server: can't bind local address");
		exit(1);
	}

	listen(sockfd, MAX_CLIENTS);
	
	clilen = sizeof(cli_addr);
	int servnum = 0;
	for (;;) {

		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
		nfds = sockfd;

		
        LIST_FOREACH(check,&head,entries)
		{
			newsockfd = check->filedesc;
			if(newsockfd>0)
            {
                FD_SET(newsockfd,&readfds);
            }
			if (newsockfd > nfds) 
            {
                nfds = newsockfd;
            }
		}
            
		int val;
		// send the ip aswell// extract from the assigment struct
		if((val = select(nfds+1, &readfds, NULL,NULL,NULL))<0)
		{
			perror("directory select has failed");
			continue;
		}
		else if(val == 0) {
			perror("directory has nothing to slect");
			continue;
		}
			if(FD_ISSET(sockfd,&readfds))
			{
				newsockfd = accept(sockfd, (struct sockaddr*) &cli_addr, &clilen);
				if(newsockfd < 0){
					perror("server: accept error");
                    exit(1);
				}
				//if(read(newsockfd,s,MAX)<0){
					//perror("Not able to read from server");
					//exit(1);
				//}
				// create the new entry
				struct entry *n = calloc(1,sizeof(struct entry));
				memset(s_out,0,sizeof(s_out));
				//tell the client it can send its request
				snprintf(s_out,MAX,"%c",'3');
				write(newsockfd,s_out,MAX);
				// save the file descriptpr
				n->filedesc = newsockfd;
				// add user to linked list
				LIST_INSERT_HEAD(&head,n,entries);
				printf("new user added\n");
						
			}
	
		LIST_FOREACH(check,&head,entries)
		{
			newsockfd = check->filedesc;
			// i dont need to check the the nodes for messages because once they have been added they can be closed
			// loop through all servers on list  and check message to see if server or client
			//?? if i am handling both server and clients wont they both need to be added to the list
			//?? if both are on list how do you differentiate between them 
                if (FD_ISSET(newsockfd, &readfds)) {
                    long int l;
                // read the message and check first value
                   if(( l=read(newsockfd,s_in,MAX))<0)
				   {
					perror("Not able to read from someone");
					continue;
					}
					else if(l == 0){
						printf("user diconnectd\n");
						servnum--;
						LIST_REMOVE(check,entries);
						close(newsockfd);
						free(check);
						continue;
					}
					
					if(s_in[0] == '*')
					{
						/// check for all possible arguments make co can hav espaces [%s]
						// the check for all values is done on the client side
						int result = sscanf(s_in,"* %s %d",check->topic,&check->port);
						if (result == 2) {
							printf("Successfully read topic: %s and port: %d\n", check->topic, check->port);
						} else {
							printf("Failed to read all values. Result: %d\n", result);
						}
						if (inet_ntop(AF_INET, &cli_addr.sin_addr, check->ip, IP_LEN) == NULL) 	
						{
							// check if inet_ntop sets error number
						perror("Failed to convert IP address");
						//free(con); // Free memory if conversion fails
						break;
						}
						if(servnum < 1){
							servnum++;
							memset(s_out,0,sizeof(s_out));
							snprintf(s_out,MAX,"%c",'1');
						}
						else{
						LIST_FOREACH(con,&head,entries)
						{
							// must check this way becasue if it is the first server it will always evaluate false sinc its checking itslef
							if(con != check)
							{
								if(strncmp(con->topic, check->topic, MAX) == 0)
								{
									memset(s_out,0,sizeof(s_out));
									snprintf(s_out,MAX,"%c",'2');
									servnum++;
									break;
								}
								else{
									servnum++;
									memset(s_out,0,sizeof(s_out));
									snprintf(s_out,MAX,"%c",'1');
								}
							}
							
						}
						}
						
						
						write(newsockfd,s_out,MAX);
					}
					else if(s_in[0] == 'l'){
						// gives the form they will be in
						LIST_FOREACH(con,&head,entries)
						{
							
							if(con->port != 0)
							{
								memset(list,0,sizeof(list));
								//sends the topic
								
								snprintf(list,500,"%s:%s:%d",con->topic,con->ip,con->port);
								
								write(newsockfd,list,500);
								// sends iip
								/*
									snprintf(s_out,MAX,"%s",check->ip);
								write(newsockfd,s_out,MAX);
								// sends the port
								snprintf(s_out,MAX,"%d",check->port);
								write(newsockfd,s_out,MAX);
								// sends a blank line for diferetiation
								write(newsockfd,nullifier,MAX);	
								*/
								
							}
						
						}
						// siganls end of servers
						char msg[500] = "Input selection from list";
						write(newsockfd,msg,500);
					}
		
				}
	
		} 
		

	}
}
*/