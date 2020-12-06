// You need disphelper (http://disphelper.sourceforge.net/) to compile it 
// gcc -c brute-capi.c -o brute12.o
// gcc brute12.o disphelper.o -o brute12.exe -lole32 -loleaut32 -luuid

#include <stdio.h>
#include <ole2.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "disphelper.h"


int main (int argc, char *argv[]){

	char password[31];
	int hr;
	int words = 0;
	int index = 0;
	char *passclean;
	time_t rawtime;
	struct tm * timeinfo;
	
	DISPATCH_OBJ(capi);
	dhInitialize(TRUE);
	dhToggleExceptions(FALSE);
	
	hr=dhCreateObject(L"CAPICOM.Certificate", NULL,  &capi);
	
	FILE *Dict;
	
	printf ("Brute12 31032008\n\n") ;
	printf ("http://www.security-projects.com/?Brute12\n") ;
	printf ("yjesus@security-projects.com\n\n\n") ;
	
	
	if(argc != 3) {
		
		printf("usage: %s [pkcs12/pfx file] [Dict file]\n\n", argv[0]);
		exit (1);
		
	} 
	
	printf("[*]Start\n");
	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	printf ( "The current date/time is: %s", asctime (timeinfo) );
	
	
	Dict = fopen(argv[2], "r");
	
	while (!feof(Dict)) {
	
		int len ;
		
		fgets(password, 31, Dict);
		
		len = strlen(password);
		if(password[len-1] == '\n' )
		password[len-1] = 0;
		
		words++;
		index++;
		
		if (index == 1000) {
			
			index = 0;
			time ( &rawtime );
			timeinfo = localtime ( &rawtime );
			printf ( "Words tested: %i\n", words);
			printf ( "The current date/time is: %s", asctime (timeinfo) );
			
		}
			
		
		hr =dhCallMethod(capi, L".Load(%s,%s, NULL, NULL)",  argv[1], password);
		
		//printf("%i\n", hr) ;
		
		if (hr ==0) {
			
			printf("\nPKCS12 Deciphered !!\n");
			printf("password:%s\n", password);
			time ( &rawtime );
			timeinfo = localtime ( &rawtime );
			printf ( "The current date/time is: %s", asctime (timeinfo) );
			goto clean;
			
		}
		
		
	}
	
	printf("[*]End\n");
	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	printf ( "The current date/time is: %s", asctime (timeinfo) );
	printf ( "Words tested: %i", words);
	
	clean:
		if (capi) SAFE_RELEASE(capi);
		dhUninitialize(TRUE);
		exit(0);
	
}
