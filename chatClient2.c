#include <stdio.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include "inet.h"
#include "common.h"
#define IP_LEN 16

int main()
{
		char s_in[MAX] = {'\0'};
		char s_out[MAX] = {'\0'};
		fd_set			readset;
		int				sockfd,sersockfd;
		struct sockaddr_in serv_addr,dir_addr;
		//
		char  chataddy[IP_LEN] = {'\0'};
		short unsigned int chatport;
		char list[500]= {'\0'};
		char msg[500] = "Input selection from list";
		bool linked = false;
		/* Set up the address of the server to be contacted. */
		// read possible comamnd line arguments for conection
		memset((char *) &dir_addr, 0, sizeof(dir_addr));
		dir_addr.sin_family			= AF_INET;
		dir_addr.sin_addr.s_addr	= inet_addr(SERV_HOST_ADDR);
		dir_addr.sin_port			= htons(SERV_TCP_PORT);

		/* Create a socket (an endpoint for communication). */
		if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			perror("client: can't open stream socket");
			exit(1);
		}
		
		/* Connect to the server. */
		if (connect(sockfd, (struct sockaddr *) &dir_addr, sizeof(dir_addr)) < 0) {
			perror("client: can't connect to server");
			exit(1);
		}
		read(sockfd,s_in,MAX);
		if(s_in[0] == '3'){
			memset(s_out,0,sizeof(s_out));
			snprintf(s_out,MAX,"%s","l");
			write(sockfd,s_out,MAX);
		}
		char form[MAX] = "topic:ip:port";
		printf("printed in the following format(%s)\n",form);
		while(strncmp(list,msg,500) != 0)
		{
			memset(list,0,sizeof(list));
			read(sockfd,list,500);
			printf("%s\n",list);
			
		}
		printf("Enter server to connect to in the format: port ip (ex 1423 124.252.33.2)\n");
		while (!linked) 
		{
			if (scanf("%hu %s", &chatport, chataddy) != 2) {
				printf("Invalid entry, please reenter\n");
				// Clear input buffer
				while (getchar() != '\n');
				continue;
			}

			// Validate chataddy
			if (inet_addr(chataddy) == INADDR_NONE) {
				perror("Invalid ip adress, please reenter");
				continue;
			} 
			else if(chatport <= 0||chatport > 65534){
				printf("invalid port number\n");
				continue;
			}
			else {
				linked = true;
			}
   		}

	

		/* Create a socket (an endpoint for communication). */
		if ((sersockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			perror("client: can't open stream socket");
			exit(1);
		}
			memset((char *) &serv_addr, 0, sizeof(serv_addr));
			serv_addr.sin_family			= AF_INET;
			serv_addr.sin_addr.s_addr	= inet_addr(chataddy);
			serv_addr.sin_port			= htons(chatport);
		/* Connect to the server. */
		if (connect(sersockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
			perror("client: can't connect to server");
			exit(1);
		}
		for(;;) {

			FD_ZERO(&readset);
			FD_SET(STDIN_FILENO, &readset);
			FD_SET(sersockfd, &readset);
			memset(s_out,0,sizeof(s_out));
			memset(s_in,0,sizeof(s_in));
			if (select(sersockfd+1, &readset, NULL, NULL, NULL) > 0)
			{
				/* Check whether there's user input to read */
				if (FD_ISSET(STDIN_FILENO, &readset)) 
			{
				scanf("%s",s_out);
				if (s_out != NULL)
				{
					// read the line
					s_out[strcspn(s_out, "\n")] = '\0'; // removes newline
					write(sersockfd, s_out, MAX); // safer alternative
				} else 
				{
					printf("Error reading or parsing user input\n");
					break;
				}
			}
				

				/* Check whether there's a message from the server to read */
				if (FD_ISSET(sersockfd, &readset)) {
					memset(s_in,0,sizeof(s_in));
					if ((read(sersockfd, s_in, MAX)) <= 0) {
						printf("server has shut down\n");
						close(sersockfd);
						exit(0);
					} else {
						printf("%s\n", s_in);
					}
				}
			}
		}
		close(sersockfd);
}

