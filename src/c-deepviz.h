/*
* Copyright (c) 2016 Saferbytes s.r.l.s.
*
* You can redistribute it and/or modify it under the terms of the MIT license.
* See LICENSE for details.
*/

#ifndef C_DEEPVIZ_H
#define C_DEEPVIZ_H

/* ******************** c-deepviz version ******************** */

#define		C_DEEPVIZ_VERSION			"1.0"
#define		C_DEEPVIZ_MAJOR_VERSION		1
#define		C_DEEPVIZ_MINOR_VERSION		0


#ifdef _WIN32
/*  Microsoft */

    #include <windows.h>
    #include <WinInet.h>
    #pragma comment (lib, "wininet.lib")

    #define EXPORT __declspec(dllexport)

#elif defined(__linux__)
/*  linux */

	#include <string.h>
	#include <errno.h>
    #include <dirent.h>
	#include <curl/curl.h>

    #define EXPORT __attribute__((visibility("default")))

#else
	#define EXPORT
#endif


/* Data types */

typedef		int					deepviz_bool;
#define		deepviz_true		1
#define		deepviz_false		0

/* DEEPVIZ REST API URLs */

#define		DEEPVIZ_SERVER					"api.deepviz.com"

#define		URL_DOWNLOAD_REPORT				"general/report"
#define		URL_UPLOAD_SAMPLE				"sandbox/submit"
#define		URL_DOWNLOAD_SAMPLE				"sandbox/sample"

#define		URL_INTEL_IP					"intel/network/ip"
#define		URL_INTEL_DOMAIN				"intel/network/domain"
#define		URL_INTEL_SEARCH				"intel/search"
#define		URL_INTEL_SEARCH_ADVANCED		"intel/search/advanced"

#ifdef __cplusplus
extern "C" {
#endif


/* ******************** Data structures ******************** */

#define     DEEPVIZ_ENTRY_MAX_LEN		256

/* c-deepviz result status codes */
typedef enum _DEEPVIZ_RESULT_STATUS {
	DEEPVIZ_STATUS_SUCCESS,
	DEEPVIZ_STATUS_INPUT_ERROR,
	DEEPVIZ_STATUS_NETWORK_ERROR,
	DEEPVIZ_STATUS_CLIENT_ERROR,
	DEEPVIZ_STATUS_SERVER_ERROR,
	DEEPVIZ_STATUS_INTERNAL_ERROR,
} DEEPVIZ_RESULT_STATUS;

/* c-deepviz result data structure */
typedef struct _DEEPVIZ_RESULT{
	DEEPVIZ_RESULT_STATUS	status;
	char*					msg;
}DEEPVIZ_RESULT, *PDEEPVIZ_RESULT;

typedef struct _DEEPVIZ_LIST{
	size_t		maxEntryNumber;
	char		entry[1][DEEPVIZ_ENTRY_MAX_LEN];			/* Will be allocated correctly by the deepviz_list_init() API */
}DEEPVIZ_LIST, *PDEEPVIZ_LIST;


/* ******************** Exported APIs ******************** */

/* Initialize a DEEPVIZ_LIST structure (size = "maxEntryNumber") */
EXPORT PDEEPVIZ_LIST	deepviz_list_init(size_t maxEntryNumber);

/* Add a new element into a DEEPVIZ_LIST. The list must be initilized before using deepviz_list_init() */
EXPORT deepviz_bool		deepviz_list_add(PDEEPVIZ_LIST list, const char* newFilter);

/* Free the allocated memory for a DEEPVIZ_RESULT */
EXPORT void				deepviz_result_free(PDEEPVIZ_RESULT result);

/* Free the allocated memory for a DEEPVIZ_LIST */
EXPORT void				deepviz_list_free(PDEEPVIZ_LIST list);

/* Sandbox */

/* Upload a sample */
EXPORT PDEEPVIZ_RESULT	deepviz_upload_sample(
	const char* api_key, 
	const char* path);

/* Upload all the files in a folder */
EXPORT PDEEPVIZ_RESULT	 deepviz_upload_folder(
	const char* api_key, 
	const char* folder);

/* Download a sample */
EXPORT PDEEPVIZ_RESULT	 deepviz_sample_download(
	const char* md5, 
	const char* api_key, 
	const char* path);

/* Retrieve the report of a sample according to the given filters */
EXPORT PDEEPVIZ_RESULT	 deepviz_sample_report(
	const char* md5, 
	const char* api_key, 
	PDEEPVIZ_LIST filters);

/* Retrieve the analysis result of a sample */
EXPORT PDEEPVIZ_RESULT	 deepviz_sample_result(
	const char* md5, 
	const char* api_key);

/* Threat Intelligence */

/* Retrieve intel data about one or more IPs
OR
   Retrieve the list of IPs analyzed in the last "time_delta" */
EXPORT PDEEPVIZ_RESULT	deepviz_ip_info(
	const char* api_key, 
	PDEEPVIZ_LIST ipList, 
	const char* time_delta, 
	deepviz_bool history);

/* Retrieve intel data about one or more domains 
OR
   Retrieve newly registered domains in the last "time_delta" */
EXPORT PDEEPVIZ_RESULT	deepviz_domain_info(
	const char* api_key, 
	PDEEPVIZ_LIST domain, 
	const char* time_delta, 
	deepviz_bool history,
	PDEEPVIZ_LIST filters);

/* Run generic search based on strings (find all IPs, domains, samples related to the searched keyword) */
EXPORT PDEEPVIZ_RESULT	 deepviz_search(
	const char* api_key, 
	const char* search_string, 
	int start_offset, 
	int elements);

/* Run advanced search based on parameters (find all MD5 samples connecting to a domain and determined as malicious) */
EXPORT PDEEPVIZ_RESULT  deepviz_advanced_search(
	const char* api_key,
	PDEEPVIZ_LIST sim_hash,
	PDEEPVIZ_LIST created_files,
	PDEEPVIZ_LIST imp_hash,
	PDEEPVIZ_LIST url,
	PDEEPVIZ_LIST strings,
	PDEEPVIZ_LIST ip,
	PDEEPVIZ_LIST asn,
	const char* classification,
	PDEEPVIZ_LIST rules,
	PDEEPVIZ_LIST country,
	deepviz_bool never_seen,
	const char* time_delta,
	const char* ip_range,
	PDEEPVIZ_LIST domain,
	int start_offset,
	int elements);


#ifdef __cplusplus
}
#endif

#endif