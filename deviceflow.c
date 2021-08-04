/*******************************************************************************
 * author:      Huan Liu
 * description: PAM module to use device flow
*******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <curl/curl.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

/* needed for base64 decoder */
#include <openssl/pem.h>

#define authorizeUrl  "https://dev-57525606.okta.com/oauth2/v1/device/authorize"
#define tokenUrl "https://dev-57525606.okta.com/oauth2/v1/token"
#define clientID "0oa15wulqt5yqD9FP5d7"

/* structure used for curl return */
struct MemoryStruct {
  char *memory;
  size_t size;
};

char *base64decode (const void *b64_decode_this, int decode_this_many_bytes){
    BIO *b64_bio, *mem_bio;      //Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
    char *base64_decoded = calloc( (decode_this_many_bytes*3)/4+1, sizeof(char) ); //+1 = null.
    b64_bio = BIO_new(BIO_f_base64());                      //Initialize our base64 filter BIO.
    mem_bio = BIO_new(BIO_s_mem());                         //Initialize our memory source BIO.
    BIO_write(mem_bio, b64_decode_this, decode_this_many_bytes); //Base64 data saved in source.
    BIO_push(b64_bio, mem_bio);          //Link the BIOs by creating a filter-source BIO chain.
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);          //Don't require trailing newlines.
    int decoded_byte_index = 0;   //Index where the next base64_decoded byte should be written.
    while ( 0 < BIO_read(b64_bio, base64_decoded+decoded_byte_index, 1) ){ //Read byte-by-byte.
        decoded_byte_index++; //Increment the index until read of BIO decoded data is complete.
    } //Once we're done reading decoded data, BIO_read returns -1 even though there's no error.
    BIO_free_all(b64_bio);  //Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
    return base64_decoded;        //Returns base-64 decoded data with trailing null terminator.
}

/* function to write curl output */
static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if(!ptr) {
    /* out of memory! */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }

  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

/* parse JSON output looking for value for a key. Assume string key value, so it parses on \" boundary */
char * getValueForKey(char * in, const char * key) {
	char * token = strtok(in, "\"");
        while ( token != NULL ) {
        	if (!strcmp(token, key)) {
                	token = strtok(NULL, "\""); /* skip : */
                        token = strtok(NULL, "\"");
			return token;
		}
		token = strtok(NULL, "\"");
	}
	return NULL;
}

CURL *curl;
struct MemoryStruct chunk;

void issuePost(char * url, char * data) {
        /* send all data to this function  */
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        /* we pass our 'chunk' struct to the callback function */
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        curl_easy_setopt(curl, CURLOPT_URL, url ) ;
        curl_easy_setopt(curl, CURLOPT_POST, 1);  /* this is a POST */
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        int res = curl_easy_perform( curl ) ;
}


void
sendPAMMessage(pam_handle_t *pamh, char * prompt_message) {
        int retval;
	//char * resp;
        
//	retval = pam_prompt(pamh, PAM_TEXT_INFO, &resp, "%s", prompt_message);
      
	struct pam_message msg[1],*pmsg[1];
        struct pam_response *resp;
        struct pam_conv *conv ;

        pmsg[0] = &msg[0] ;
        msg[0].msg_style = PAM_TEXT_INFO ;
        msg[0].msg = prompt_message;

        resp = NULL ;

        retval = pam_get_item( pamh, PAM_CONV, (const void **) &conv ) ;
        if( retval==PAM_SUCCESS ) {
                retval = conv->conv( 1, (const struct pam_message **) pmsg, &resp, conv->appdata_ptr ) ;
        }
        if( resp ) {
                free( resp );
        }
}



extern char * getQR(char * str);

/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
        return PAM_SUCCESS ;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
        int res ;
	char postData[1024];

        fprintf(stderr, "starting\n");

        /* memory for curl return */
        chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */
        chunk.size = 0;    /* no data at this point */

        /* init Curl handle */
        curl_global_init(CURL_GLOBAL_ALL);
        curl = curl_easy_init();

        /* hold temp string */
        char str1[4096], str2[1024], str3[1024];;

        /* call authorize end point */
	sprintf(postData, "client_id=%s&scope=openid profile offline_access", clientID); 
        issuePost(authorizeUrl, postData);

	strcpy(str1, chunk.memory);
        char * usercode = getValueForKey(str1, "user_code");
	strcpy(str2, chunk.memory);
        char * devicecode = getValueForKey(str2, "device_code");
	strcpy(str3, chunk.memory);
	char * activateUrl = getValueForKey(str3, "verification_uri");
        printf("auth: %s %s\n", usercode, devicecode);

	char prompt_message[2000];
        char * qrc = getQR(activateUrl);
  	sprintf(prompt_message, "\n\nPlease login at %s or scan the QRCode below:\nThen input code %s\n\n%s", activateUrl, usercode, qrc );
        free(qrc);
        sendPAMMessage(pamh, prompt_message);

	/* work around SSH PAM bug that buffers PAM_TEXT_INFO */ 
	char * resp;
        res = pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &resp, "Press Enter to continue:");

        int waitingForActivate = 1;
        sprintf(postData, "device_code=%s&grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=%s", devicecode, clientID);

        while (waitingForActivate) {
                // sendPAMMessage(pamh, "Waiting for user activation");

                chunk.size = 0;
                issuePost(tokenUrl, postData);

		strcpy(str1, chunk.memory);
                char * errormsg = getValueForKey(str1, "error");
                if (errormsg == NULL) {

			/* Parse response to find id_token, then find payload, then find name claim */
			char * idtoken = getValueForKey(chunk.memory, "id_token");

			char * header = strtok(idtoken, ".");
			char * payload = strtok(NULL, ".");

			char * decoded = base64decode(payload, strlen(payload));

			char * name = getValueForKey(decoded, "name");

			sprintf(prompt_message, "\n\n*********************************\n  Welcome, %s\n*********************************\n\n\n", name);
			sendPAMMessage(pamh, prompt_message);

                        if (curl) curl_easy_cleanup( curl ) ;
                        curl_global_cleanup();

                        return PAM_SUCCESS;
                }
                printf("error %s\n", errormsg);
                sleep(5);
        }
        /* Curl clean up */
        if (curl) curl_easy_cleanup( curl ) ;
        curl_global_cleanup();

        return PAM_AUTH_ERR;
}
