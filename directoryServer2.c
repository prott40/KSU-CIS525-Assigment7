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
#define IP_LEN 16
struct entry{
	int filedesc;
	int port;
	char topic[MAX];
	char ip[IP_LEN];
	
	LIST_ENTRY(entry) entries;
};

LIST_HEAD(listhead,entry);

int main(int argc, char **argv)
{
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
