#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <assert.h>
#include <signal.h>

#include "../libwebsockets/lib/libwebsockets.h"

#ifndef _WIN32
#include <syslog.h>
#include <sys/time.h>
#include <unistd.h>
#else
#include "gettimeofday.h"
#include <process.h>
#endif


#define MAX_PAYLOAD 1024

//TODO -- Remove later, only for initial test 
#define ADDRESS "echo.websocket.org"
#define PORT 443
//---------------------------------------------


typedef struct per_session_data {
        size_t rx, tx;
        unsigned char buf[LWS_PRE + MAX_PAYLOAD];
        unsigned int len;
        unsigned int index;
        int final;
        int continuation;
        int binary;
}per_session_data_t;

static volatile int force_exit = 0;

typedef struct lws_protocols lws_protocols_t;
typedef struct lws_context lws_context_t;
typedef struct lws_context_creation_info lws_context_creation_info_t;
typedef struct lws_client_connect_info lws_client_connect_info_t;
typedef struct lws lws_t;
typedef enum lws_callback_reasons lws_callback_reasons_t;

static int callback_client(lws_t *wsi, lws_callback_reasons_t reason, void *user, void *in, size_t len ){
        
	per_session_data_t *pss = (per_session_data_t *)user;
	int n;
	
	switch(reason){
		case LWS_CALLBACK_CLOSED:
		case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
			lwsl_debug("Closed\n");
			break;
		case LWS_CALLBACK_CLIENT_ESTABLISHED:
			lwsl_debug("Client has connected\n");
			pss->index = 0;
			pss->len = -1;
			break;
		case LWS_CALLBACK_CLIENT_RECEIVE:
			lwsl_notice("Client RX: %s", (char *)in);
			break;
		case LWS_CALLBACK_CLIENT_WRITEABLE:
			pss->len = sprintf((char *)&pss->buf[LWS_PRE], "Test msg");
			lwsl_notice("Client TX: %s", &pss->buf[LWS_PRE]);
			if(!lws_write(wsi, &pss->buf[LWS_PRE], pss->len, LWS_WRITE_TEXT)){
				lwsl_err("ERROR writing to socket");
				return -1;
			}
			break;
		default:
			break;
	}
	return 0;
}


static lws_protocols_t protocols[] = {
	{
		"",
		callback_client,
		sizeof(per_session_data_t),
		MAX_PAYLOAD,
	},
	{
		NULL, NULL, 0
	}
};

lws_context_t *client_init(lws_client_connect_info_t *info_ptr){
	lws_context_creation_info_t ctxt;
	memset(&ctxt, 0, sizeof ctxt);	
	int use_ssl = 2;
	char address[256], ads_port[256 + 30];
	const char *_interface = NULL;	
	const char *connect_protocol = NULL;	
	int port = 0;

	ctxt.port = CONTEXT_PORT_NO_LISTEN;
	ctxt.iface = _interface;
	ctxt.protocols = protocols;
	ctxt.ssl_cert_filepath = NULL;
	ctxt.ssl_private_key_filepath = NULL;
	ctxt.gid = -1;
	ctxt.uid = -1;
	ctxt.options = LWS_SERVER_OPTION_VALIDATE_UTF8;
	if(use_ssl)
		ctxt.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	lws_context_t *context;
	context = lws_create_context(&ctxt);
	if(context == NULL){
		lwsl_err("Context creation failed\n");
		return context;
	}
	
	strncpy(address, ADDRESS, sizeof(address)-1);
	port = PORT;
	sprintf(ads_port, "%s:%u", address, port & 65535);

	info_ptr->context = context;
	info_ptr->address = ADDRESS;
	info_ptr->port = port;
	info_ptr->ssl_connection = use_ssl;
	info_ptr->path = "/";
	info_ptr->host = ads_port;
	info_ptr->origin = ads_port;
	info_ptr->protocol = connect_protocol;
	return context;
}

void sighandler(int sig){
	force_exit = 1;
}

int main()
{
	lws_client_connect_info_t info;
	memset(&info, 0, sizeof(info));
	lws_context_t *context;
	context = client_init(&info);
	lws_t *wsi;
	lwsl_notice("Client connecting to %s:%u\n", info.address, info.port);
	wsi = lws_client_connect_via_info(&info);
	if(!wsi){
		lwsl_err("Client failed to connect to %s\n", info.host);
	}
	struct timeval tv;
	typedef unsigned long long tv_t;
	gettimeofday(&tv, NULL);
	tv_t oldus = ((unsigned long long)tv.tv_sec * 1000000) + tv.tv_usec;
	tv_t newus = oldus;
	int rate_us = 250000;

	signal(SIGINT, sighandler);	

	while(!force_exit){
		gettimeofday(&tv, NULL);
		newus = ((unsigned long long)tv.tv_usec * 1000000) + tv.tv_usec;
		if((newus - oldus) > rate_us){
			lws_callback_on_writable_all_protocol(context, &protocols[0]);
			oldus = newus;
		}
	lws_service(context, 10);
	}
	lws_context_destroy(context);
	lwsl_notice("exiting libwebsockets...\n");
	return 0;
}

