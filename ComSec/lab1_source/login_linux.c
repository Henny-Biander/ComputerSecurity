/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
#include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16

void sighandler() {
	//The signal function catches and ignores the signals below.
	/* add signalhandling routines here */
	/* see 'man 2 signal' */
	signal(SIGINT, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
}

int main(int argc, char *argv[]) {

	//struct passwd *passwddata; /* this has to be redefined in step 2 */
	/* see pwent.h */
	mypwent *passwddata;

	char important1[LENGTH] = "**IMPORTANT 1**";

	char user[LENGTH];

	char important2[LENGTH] = "**IMPORTANT 2**";

	//char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;

	//Flag is used when asking the user if they want to change their password.
	char flag;

	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important1' before input of login name: %s\n",
				important1);
		printf("Value of variable 'important2' before input of login name: %s\n",
				important2);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		//fgets is used because it specifies how many characters to take -> no buffer overflow
		if (fgets(user, LENGTH, stdin) == NULL) /* gets() is vulnerable to buffer */
			exit(0); 			/*  overflow attacks.  */
		
		//fgets is \n terminated. Replace \n with \0
		user[strcspn(user, "\n")] = '\0';
	
		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important 1' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important1);
		printf("Value of variable 'important 2' after input of login name: %*.*s\n",
		 		LENGTH - 1, LENGTH - 1, important2);

		// passwddata contains the struct with all of the information about the user.
		// returns -1 if the user doesnt exist
		passwddata = mygetpwnam(user);
		if(passwddata == NULL){
			printf("This account doesn't exist, try again.\n");
			continue;
		}
		// If the user has failed thrice with guessing the password they can not try anymore.
		// This is in order to protect against attacks which try to figure out the password.
		if(passwddata->pwfailed > 3){
			printf("You have failed too many times. \n");
			continue;
		}

		user_pass = getpass(prompt);


		if (passwddata != NULL) {
			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */

			// hashedPassword = the hashed password from the user
			char *hashedPassword = crypt(user_pass, passwddata->passwd_salt);

			// If the user enters the correct password the number of failed attempts are displayed and the counter reset.
			// The age of the password is increased by 1
			if (!strcmp(hashedPassword, passwddata->passwd)) {
				printf(" You're in !\n");
				printf(" The number of failed attempts is: %d\n", passwddata->pwfailed);
				passwddata->pwfailed = 0;
				passwddata->pwage++;
				if(mysetpwent(user, passwddata) == -1){
						exit(0);
				}
				// If the user has logged in more than 10 times with this password they are 
				// asked if they want to change their password. If they enter y they change their password.
				// Otherwise they just continue.
				if(passwddata->pwage > 10){
					printf(" Do you want to change your password [y/-]? \n");
					scanf("%c", &flag);
					if(flag == 'y'){
						char *newPass = getpass("New password: ");
						char *hashNewPass = crypt(newPass, passwddata->passwd_salt);
						passwddata->passwd = hashNewPass;
						passwddata->pwage = 0;
					}else{
						printf("You have decided not to change the password.");
					}
					if(mysetpwent(user, passwddata) == -1){
						exit(0);
					}
				}

				/*  check UID, see setuid(2) */
				// The setuid function is used to set the users ID when it is finnished logging in.
				// Then the comand interpreter is started
				if( setuid(getuid()) == -1){
					exit(0);
				}
				setuid(getuid());
				execve("/bin/sh", NULL, NULL);
			

			}else{
				passwddata->pwfailed++;

				if(mysetpwent(user, passwddata) == -1){
						exit(0);
					}
			}
		}
		printf("Login Incorrect \n");
	}
	return 0;
}
