/*
* Copyright (c) 2016 Saferbytes s.r.l.s.
*
* You can redistribute it and/or modify it under the terms of the MIT license.
* See LICENSE for details.
*/

#ifndef C_DEEPVIZ_PRIVATE_H
#define C_DEEPVIZ_PRIVATE_H

#include "c-deepviz.h"
#include <stdio.h>

/* Jansson import */
#include "../external-libs/jansson-2.7/jansson.h"

#ifdef _WIN32
	#ifndef _WIN64
	/* 32 bit */
		#ifdef _DEBUG
			#pragma comment (lib,"../external-libs/jansson-2.7/windows/Win32/jansson_d.lib")
		#else
			#pragma comment (lib,"../external-libs/jansson-2.7/windows/Win32/jansson.lib")
		#endif
	#else
	/* 64 bit */
		#ifdef _DEBUG
			#pragma comment (lib,"../external-libs/jansson-2.7/windows/x64/jansson_d.lib")
		#else
			#pragma comment (lib,"../external-libs/jansson-2.7/windows/x64/jansson.lib")
		#endif
	#endif
#endif

//#define		DEEPVIZ_USER_AGENT			"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"

#define		DEEPVIZ_HTTP_HEADER_CTJ		"Content-Type: application/json"
#define		DEEPVIZ_HTTP_HEADER_CTM		"Content-Type: multipart/form-data"
#define		DEEPVIZ_HTTP_HEADER_A		"Accept: */*"
#define		DEEPVIZ_HTTP_HEADER_AE		"Accept-Encoding : gzip, deflate"

#define		DEEPVIZ_BOUNDARY			"----WebKitFormBoundary5YdJYkfUfp3wEFnh"

#define		DEEPVIZ_FILEPATH_MAX_LEN	512
#define		DEEPVIZ_PAYLOAD_MAX_LEN		512
#define     DEEPVIZ_ERROR_MAX_LEN      	512
#define		DEEPVIZ_HTTP_HEADER_MAX_LEN	256
#define		DEEPVIZ_STATUS_CODE_MAX_LEN 100

#define     DEEPVIZ_MULTIPART_SOURCE	"c_deepviz"


/* ============================ private functions ============================ */

int					dvz_vsnprintf(char *outBuf, size_t size, const char *format, va_list ap);
int					deepviz_sprintf(char *outBuf, size_t size, const char *format, ...);
PDEEPVIZ_RESULT		deepviz_result_init(DEEPVIZ_RESULT_STATUS status, char* msg);
PDEEPVIZ_RESULT		parse_deepviz_response(const char* statusCode, void* response, size_t responseLen);


#if defined(_WIN32)
/*  Microsoft */

deepviz_bool	win_sendHTTPrequest(const char* httpServerName,
									const char* httpPage,
									DWORD connectionFlags,
									const char* HTTPheader,
									DWORD requestFlags,
									PVOID requestBuffer,
									size_t requestBufferLen,
									char* statusCodeOut,
									size_t statusCodeOutLen,
									PVOID *responseOut,
									size_t *responseOutLen,
									char* errorMsg);

#elif defined(__linux__)
/* linux */

struct MemoryStruct {
	char *memory;
	size_t size;
};

deepviz_bool linux_sendHTTPrequest(	  const char* serverName,
									  const char* httpPage,
									  const char* requestBuffer,
									  char* statusCodeOut,
									  size_t statusCodeOutLen,
									  void** responseOut,
									  size_t *responseOutLen,
									  char* errorMsg);

deepviz_bool linux_sendHTTPrequestMultipart(   const char* serverName,
											   const char* httpPage,
											   const char* apikey,
											   const char* filePath,
											   char* statusCodeOut,
											   size_t statusCodeOutLen,
											   void** responseOut,
											   size_t *responseOutLen,
											   char* errorMsg);

#endif

#endif //C_DEEPVIZ_PRIVATE_H
