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

char orgUrl[] = "https://huanliu.trexcloud.com";

/* structure used for curl return */
struct MemoryStruct {
  char *memory;
  size_t size;
};

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

void getValueForKey(const char * in, const char * key, int start, int len, char * result) {
        char * p = strstr(in, key);

        if (p == NULL)
                result[0] = 0;
        else {
                strncpy( result, p+start , len );
                result[len] = 0;
        }
}

CURL *curl;
struct MemoryStruct chunk;

void issuePost(char * url, char * data) {
        /* send all data to this function  */
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        /* we pass our 'chunk' struct to the callback function */
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        curl_easy_setopt( curl, CURLOPT_URL, url ) ;
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

        fprintf(stderr, "starting\n");

        /* memory for curl return */
        chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */
        chunk.size = 0;    /* no data at this point */

        /* init Curl handle */
        curl_global_init(CURL_GLOBAL_ALL);
        curl = curl_easy_init();

        /* hold returned user_code */
        char usercode[10], devicecode[35];

        /* call authorize end point */
        issuePost("https://huanliu.trexcloud.com/oauth2/v1/device/authorize", "client_id=devNativeClientId&scope=openid profile offline_access");

        getValueForKey(chunk.memory, "user_code", 12, 8, usercode);
        getValueForKey(chunk.memory, "device_code", 14, 36, devicecode);
        printf("auth: %s %s\n", usercode, devicecode);


	char prompt_message[2000];
        char * qrc = getQR("https://huanliu.trexcloud.com/activate");
  	sprintf( prompt_message, "\n\nPlease login at https://huanliu.trexcloud.com/activate or scan the QRCode below:\nThen input code %s\n\n%s", usercode, qrc );
        free(qrc);
        sendPAMMessage(pamh, prompt_message);

	/* work around SSH PAM bug that buffers PAM_TEXT_INFO */ 
	char * resp;
        res = pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &resp, "Press Enter to continue:");

        int waitingForActivate = 1;
        char postData[1024];
        sprintf(postData, "device_code=%s&grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=devNativeClientId", devicecode);

        char errormsg[256];
        while (waitingForActivate) {
                // sendPAMMessage(pamh, "Waiting for user activation");

                chunk.size = 0;
                issuePost("https://huanliu.trexcloud.com/oauth2/v1/token", postData);

                getValueForKey(chunk.memory, "error", 8, 10, errormsg);
                if (errormsg[0] == 0) {
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
