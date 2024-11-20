#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/queue.h>
#include <string.h>
#include "inet.h"
#include "common.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

struct entry{
	int filedesc;
    int mesnum;
	char name[MAX];
	LIST_ENTRY(entry) entries;
};


LIST_HEAD(listhead,entry);

SSL_CTX *create_chat_server_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    
    // Load Chat Server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "chat_server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, "chat_server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(1);
    }

    return ctx;
}

void verify_chat_server_certificate(SSL *ssl, const char *expected_topic) {
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL) {
        printf("No certificate presented by the Chat Server\n");
        exit(1);
    }

    X509_NAME *subject_name = X509_get_subject_name(cert);
    char cn[256];
    X509_NAME_get_text_by_NID(subject_name, NID_commonName, cn, sizeof(cn));
    
    if (strcmp(cn, expected_topic) != 0) {
        printf("Certificate CN mismatch. Expected '%s', but got '%s'\n", expected_topic, cn);
        exit(1);
    }

    X509_free(cert);
}


int find_name(struct entry * pt, struct entry* check, char name[],struct listhead head) {
    // while there is still users to check
    LIST_FOREACH(pt,&head,entries){
       // compare the nameto each user
        if(strncmp(pt->name, name, MAX) == 0)
        {           
            // break connection and tell the server what happened
            printf("user with duplicate name\n");
            write(check->filedesc, "Nickname taken. Disconnecting.\n", 31);
            close(check->filedesc);
            LIST_REMOVE(check,entries);
            free(check);
            
            return 1;  // Nickname taken
                     
        }
    }  
    // when the user name is not used  
    write(check->filedesc, "Nickname accepted!\n", 19);
    snprintf(check->name,MAX,"%s", name);
    
    return 0;  // Nickname accepted    

}
int main(int argc, char **argv)
{
    SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	int				sockfd, newsockfd,dirsockfd;
	unsigned int	clilen;
	struct sockaddr_in cli_addr, serv_addr, dir_addr;
	char				s_in[MAX];
    char				s_out[MAX];
    int usrnum = 0;
    char arrive[MAX] = "has arrived in the chat";
    char dis[MAX] = "user disconnected";
    short unsigned int port;
    //struct HEADNAME *headptr;
	struct listhead head;
    int topic_accpet = 0;
    int nfds; // is the largest number of descriptors ask if this need to be sent to max clients
    fd_set readfds, serfds; 
    struct entry * check;
    
    struct entry * pt;
    LIST_INIT(&head);
    
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
    }

	/* Create communication endpoint */
    // croect with connect but after need to stay connected with directory so we can see if the topic is accepted
    // need to have different sockets for directory connection and client connection
    // initialize checks for linked list ahead of time
    // have directory hanlde topic selection and dynaically wiat for the to write back
    //
    if ((dirsockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    {
        perror("server: can't open stream socket");
        exit(1);
    }

	/* Bind socket to local address */
	memset((char *) &dir_addr, 0, sizeof(dir_addr));
	dir_addr.sin_family			= AF_INET;
	dir_addr.sin_addr.s_addr	= inet_addr(SERV_HOST_ADDR);
	dir_addr.sin_port			= htons(SERV_TCP_PORT);
    
   
	// GO THROUGH LOGIC AND MAKE SURE IT IS THROUGHLY CLEAR
    if (connect(dirsockfd, (struct sockaddr *) &dir_addr, sizeof(dir_addr)) < 0) {
			perror("client: can't connect to server");
			exit(1);
	}
    //write(dirsockfd,s_out,MAX);
    while(topic_accpet == 0){
            FD_ZERO(&readfds);
			FD_SET(dirsockfd, &readfds);
            
			if (select(dirsockfd+1, &readfds, NULL, NULL, NULL) > 0)
			{
				/* Check whether there's a message from the server to read */
				if (FD_ISSET(dirsockfd, &readfds)) {
                    memset(s_in,0,sizeof(s_in));
					if ((read(dirsockfd, s_in, MAX)) <= 0) {
						printf("server has shut down\n");
						close(dirsockfd);
						exit(0);
					} else {
						switch(s_in[0])
                        {
                            case '1':
                                printf("topic is accpeted\n");
                                topic_accpet =1;
                                break;
                            case '2':
                                printf("topic denied exiting\n");
                                close(dirsockfd);
                                exit(1);
                                break;
                            case '3':
                                write(dirsockfd,s_out,MAX);
                                break;
                            default:
                                printf("nothing that was supposed to be made it\n");
                                exit(1);
                                
                        }
					}
				}
			}
    }
    

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    {
        perror("server: can't open stream socket");
        exit(1);
    }

    memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family			= AF_INET;
	serv_addr.sin_addr.s_addr	= htonl(INADDR_ANY);
	serv_addr.sin_port			= htons(port); 
     
	/* Add SO_REAUSEADDR option to prevent address in use errors (modified from: "Hands-On Network
	* Programming with C" Van Winkle, 2019. https://learning.oreilly.com/library/view/hands-on-network-programming/9781789349863/5130fe1b-5c8c-42c0-8656-4990bb7baf2e.xhtml */
	int true = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&true, sizeof(true)) < 0) {
		perror("server: can't set stream socket address reuse option");
		exit(1);
	}

	 
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("server: can't bind local address");
		exit(1);
	}
    printf("making it to listen\n");
//
	listen(sockfd, MAX_CLIENTS);
    clilen = sizeof(cli_addr);
    printf("begign accept\n");    
    memset(s_out,0,sizeof(s_out));
    memset(s_in,0,sizeof(s_in));
    printf("server is open for connection\n");
	for (;;) 
    {
        
		FD_ZERO(&serfds); // clears the readfds
        FD_SET(sockfd, &serfds); // sets the server socket in the fd set
        
        nfds = sockfd; // sets the max file descriptor number
     
        LIST_FOREACH(check,&head,entries)
		{
			newsockfd = check->filedesc;
			if(newsockfd>0)
            {
                FD_SET(newsockfd,&serfds);
            }
			if (newsockfd > nfds) 
            {
                nfds = newsockfd;
            }
		}

        
        int v;
        if((v = select(nfds+1, &serfds, NULL,NULL,NULL))<0)
		{
			perror("directory select has failed");
			continue;
		}
		else if(v == 0) {
			perror("directory has nothing to slect");
			continue;
		}

            // Accept a ne
            // acce[pt the new client in this check 
            if (FD_ISSET(sockfd, &serfds)) 
            {
                clilen = sizeof(cli_addr);
                // this is checking lisening socket for connection and connecting listening socket
                newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
                if (newsockfd < 0) 
                {
                    perror("server: accept error");
                    exit(1);
                }
                // adds the node to revice messages and if it sthe first t notifes the user they are first
                struct entry * tt;
                tt = malloc(sizeof(struct entry));
                if (tt == NULL) {
                    // Handle malloc failure
                    perror("malloc failed");
                    exit(EXIT_FAILURE);
                }
                tt->filedesc = newsockfd;
                tt->mesnum = 0;
                
                LIST_INSERT_HEAD(&head,tt,entries);
                
                // ask for new nickname
                printf("created new node\n");
                if(usrnum < 1){
                    char r[MAX] = "You are the first user\nEnter your nickname:";
                    write(newsockfd,r,MAX);
                    usrnum++;
                }else{
                    write(newsockfd, "Enter your nickname:",21);
                    usrnum++;
                }
                
            }
            // look at the front of the list
            // keep this for each do the same in the directory
            
            LIST_FOREACH(check,&head,entries)
            {
                check->filedesc;
                // check for disconnects 
                // set the default messages
                // have the server print all messages aswell
                char msg[MAX] = {'\0'};// clear print line
                char n[MAX] = {'\0'};
                
                //char n[MAX];
                // upon a input on a user
                if (FD_ISSET(check->filedesc, &serfds)) {
                    // clear the message string
                    memset(s_in,0,sizeof(s_in));
                    // read the message and check its length
                    long int valread = read(check->filedesc, s_in, MAX);
                     snprintf(n,MAX,"%s",check->name);
                    if (check->mesnum == 0) 
                    {
                       int rt = find_name(pt, check, s_in,head);
                        check->mesnum++;
                        if(rt == 0)
                        {
                            // notify all of the users that a new user has arrived
                            snprintf(n,MAX,"%s",check->name);
                            snprintf(s_in,MAX,"%s",arrive);
                            printf("new user accepted\n");
                        }
                        if(rt == 1){
                            printf("user already taken\n");
                            usrnum--;// the user endered a already use nickname
                            break;
                        }
                    } //
                    // If the disconnects
                    if (valread <= 0)
                    {
                        // Handle client disconnect
                        printf("user diconected\n");
                        usrnum--;
                        snprintf(s_in,MAX,"%s",dis);
                        close(check->filedesc);
                        LIST_REMOVE(check,entries);
                        free(check);
                    }

                        LIST_FOREACH(pt,&head,entries)
                        {
                            n[MAX-1] = '\0';
                            snprintf(msg, MAX, "%s:%s", n, s_in);// combine name and message
                            msg[MAX-1] = '\0';
                            if (pt != check) // check that is printing to a valid user and not the writer
                                {
                                    long int sent = write(pt->filedesc, msg, MAX);// writes message
                                    if(sent <= 0)// if the socket is closed
                                    {
                                        close(pt->filedesc);// close the socker
                                        LIST_REMOVE(pt,entries);
                                        usrnum--;
                                        free(pt);
                                    }
                                }
                                    
                        }
                    
                    
                }
               
            }
        
	}
}
