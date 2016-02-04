/*
* Copyright (c) 2016 Saferbytes s.r.l.s.
*
* You can redistribute it and/or modify it under the terms of the MIT license.
* See LICENSE for details.
*/

#include "c-deepviz.h"
#include "c-deepviz_private.h"

EXPORT PDEEPVIZ_RESULT deepviz_ip_info(const char* api_key,
										PDEEPVIZ_LIST ipList, 
										const char* time_delta, 
										deepviz_bool history){
	PDEEPVIZ_RESULT	result;
	void*			responseOut = NULL;
	size_t			responseOutLen = 0;
	json_t			*jsonObj = NULL;
	json_t			*jsonIPs = NULL;
	char			*jsonRequestString = NULL;
	char			*retMsg = NULL;
	deepviz_bool	bRet = deepviz_false;
	size_t			i;
	char			statusCode[DEEPVIZ_STATUS_CODE_MAX_LEN] = { 0 };
#ifdef _WIN32
	char			HTTPheader[DEEPVIZ_HTTP_HEADER_MAX_LEN] = { 0 };
#endif

	retMsg = (char*)malloc(DEEPVIZ_ERROR_MAX_LEN);
	if (!retMsg){
		return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, NULL);
	}

#if !defined(_WIN32) && !defined(__linux__)
	/* TODO */
	sprintf(retMsg, "Platform not supported");
	return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, retMsg);
#endif

	if (!api_key || (!ipList && !time_delta)){
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Invalid or missing parameters. Please try again!");
		return deepviz_result_init(DEEPVIZ_STATUS_INPUT_ERROR, retMsg);
	}

	if (ipList && time_delta){
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "You must specify either a list of IPs or timestamp. Please try again!");
		return deepviz_result_init(DEEPVIZ_STATUS_INPUT_ERROR, retMsg);
	}

	/* Build IP INFO json request */

	if (ipList){
		
		/* Build ip list JSON array (if any) */
		jsonIPs = json_array();
		for (i = 0; i < ipList->maxEntryNumber; i++){
			if (ipList->entry[i][0]){
				json_array_append_new(jsonIPs, json_string(ipList->entry[i]));
			}
		}

		if (json_array_size(jsonIPs) == 0){
			json_decref(jsonIPs);
			deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "You must provide one or more IPs. Please try again!");
			return deepviz_result_init(DEEPVIZ_STATUS_INPUT_ERROR, retMsg);
		}

		jsonObj = json_pack("{ssssso}",
							"api_key", api_key,
							"history", (history == deepviz_true ? "true" : "false"),
							"ip", jsonIPs);
	}
	else if (time_delta){
	
		jsonObj = json_pack("{ssssss}",
							"api_key", api_key,
							"history", (history == deepviz_true ? "true" : "false"),
							"time_delta", time_delta);

	}

	/* Dump JSON string */
	jsonRequestString = json_dumps(jsonObj, 0);

	if (jsonIPs) json_decref(jsonIPs);
	json_decref(jsonObj);

	if (!jsonRequestString){
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Error creating HTTP request");
		return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, retMsg);
	}

#ifdef _WIN32
/* Windows */

	sprintf_s(HTTPheader, DEEPVIZ_HTTP_HEADER_MAX_LEN, "%s\r\n%s\r\n%s\r\n", DEEPVIZ_HTTP_HEADER_CTJ, DEEPVIZ_HTTP_HEADER_A, DEEPVIZ_HTTP_HEADER_AE);

	/* Send HTTP request */
	bRet = win_sendHTTPrequest( DEEPVIZ_SERVER,
								URL_INTEL_IP,
								INTERNET_DEFAULT_HTTPS_PORT,
								HTTPheader,
								INTERNET_FLAG_SECURE,
								jsonRequestString,
								strlen(jsonRequestString),
								statusCode,
								DEEPVIZ_STATUS_CODE_MAX_LEN,
								&responseOut,
								&responseOutLen,
								retMsg);

#elif defined(__linux__)
/* Linux */

	bRet = linux_sendHTTPrequest(	DEEPVIZ_SERVER,
									URL_INTEL_IP,
									jsonRequestString,
									statusCode,
									DEEPVIZ_STATUS_CODE_MAX_LEN,
									&responseOut,
									&responseOutLen,
									retMsg);

#endif

	free(jsonRequestString);

	if (bRet == deepviz_false){
		/* Network Error */
		if (responseOut) free(responseOut);
		return deepviz_result_init(DEEPVIZ_STATUS_NETWORK_ERROR, retMsg);
	}

	free(retMsg);
	retMsg = NULL;

	/* Parse API response and build DEEPVIZ_RESULT return value */
	result = parse_deepviz_response(statusCode, responseOut, responseOutLen);

	if (responseOut) free(responseOut);

	return result;

}


EXPORT PDEEPVIZ_RESULT deepviz_domain_info(const char* api_key,
											PDEEPVIZ_LIST domain, 
											const char* time_delta, 
											deepviz_bool history, 
											PDEEPVIZ_LIST filters){

	PDEEPVIZ_RESULT	result = NULL;
	void*			responseOut = NULL;
	size_t			responseOutLen = 0;
	json_t			*jsonObj = NULL;
	json_t			*jsonDomains = NULL;
	json_t			*jsonFilters = NULL;
	char			*jsonRequestString = NULL;
	char			*retMsg = NULL;
	deepviz_bool	bRet = deepviz_false;
	size_t			i;
	char			statusCode[DEEPVIZ_STATUS_CODE_MAX_LEN] = { 0 };
#ifdef _WIN32
	char			HTTPheader[DEEPVIZ_HTTP_HEADER_MAX_LEN] = { 0 };
#endif

	retMsg = (char*)malloc(DEEPVIZ_ERROR_MAX_LEN);
	if (!retMsg){
		return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, NULL);
	}

#if !defined(_WIN32) && !defined(__linux__)
	/* TODO */
	sprintf(retMsg, "Platform not supported");
	return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, retMsg);
#endif

	if (!api_key || (!domain && !time_delta)){
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Invalid or missing parameters. Please try again!");
		return deepviz_result_init(DEEPVIZ_STATUS_INPUT_ERROR, retMsg);
	}

	if (domain && time_delta){
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "You must specify either a list of domains or timestamp. Please try again!");
		return deepviz_result_init(DEEPVIZ_STATUS_INPUT_ERROR, retMsg);
	}

	/* Build IP INFO json request */

	/* Build filter list (if any) */
	jsonFilters = json_array();
	if (filters){
		for (i = 0; i < filters->maxEntryNumber; i++){
			if (filters->entry[i][0]){
				json_array_append_new(jsonFilters, json_string(filters->entry[i]));
			}
		}
		if (json_array_size(jsonFilters) == 0){
			json_decref(jsonFilters);
			deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "You must provide one or more output filters in a list. Please try again!");
			return deepviz_result_init(DEEPVIZ_STATUS_INPUT_ERROR, retMsg);
		}
	}

	if (domain){
		/* Domains provided */

		/* Build domain list JSON array (if any) */
		jsonDomains = json_array();
		for (i = 0; i < domain->maxEntryNumber; i++){
			if (domain->entry[i][0]){
				json_array_append_new(jsonDomains, json_string(domain->entry[i]));
			}
		}

		if (json_array_size(jsonDomains) == 0){
			json_decref(jsonDomains);
			json_decref(jsonFilters);
			deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "You must provide one or more domains. Please try again!");
			return deepviz_result_init(DEEPVIZ_STATUS_INPUT_ERROR, retMsg);
		}

		jsonObj = json_pack("{ssssso}",
							"api_key", api_key,
							"history", (history == deepviz_true ? "true" : "false"),
							"domain", jsonDomains);
	}
	else if (time_delta){
		/* time delta provided */

		jsonObj = json_pack("{ssssss}",
							"api_key", api_key,
							"history", (history == deepviz_true ? "true" : "false"),
							"time_delta", time_delta);

	}

	if (json_array_size(jsonFilters)){
		/* Filters provided, add to request */
		json_object_set_new(jsonObj, "output_filters", jsonFilters);
	}

	/* Dump JSON string */
	jsonRequestString = json_dumps(jsonObj, 0);

	if (jsonDomains) json_decref(jsonDomains);
	json_decref(jsonFilters);
	json_decref(jsonObj);

	if (!jsonRequestString){
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Error creating HTTP request");
		return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, retMsg);
	}

#ifdef _WIN32
	/* Windows */

	sprintf_s(HTTPheader, DEEPVIZ_HTTP_HEADER_MAX_LEN, "%s\r\n%s\r\n%s\r\n", DEEPVIZ_HTTP_HEADER_CTJ, DEEPVIZ_HTTP_HEADER_A, DEEPVIZ_HTTP_HEADER_AE);

	/* Send HTTP request */
	bRet = win_sendHTTPrequest( DEEPVIZ_SERVER,
								URL_INTEL_DOMAIN,
								INTERNET_DEFAULT_HTTPS_PORT,
								HTTPheader,
								INTERNET_FLAG_SECURE,
								jsonRequestString,
								strlen(jsonRequestString),
								statusCode,
								DEEPVIZ_STATUS_CODE_MAX_LEN,
								&responseOut,
								&responseOutLen,
								retMsg);

#elif defined(__linux__)
	/* Linux */

	bRet = linux_sendHTTPrequest(	DEEPVIZ_SERVER,
									URL_INTEL_DOMAIN,
									jsonRequestString,
									statusCode,
									DEEPVIZ_STATUS_CODE_MAX_LEN,
									&responseOut,
									&responseOutLen,
									retMsg);

#endif

	free(jsonRequestString);

	if (bRet == deepviz_false){
		/* Network Error */
		if (responseOut) free(responseOut);
		return deepviz_result_init(DEEPVIZ_STATUS_NETWORK_ERROR, retMsg);
	}

	free(retMsg);
	retMsg = NULL;

	/* Parse API response and build DEEPVIZ_RESULT return value */
	result = parse_deepviz_response(statusCode, responseOut, responseOutLen);

	if (responseOut) free(responseOut);

	return result;

}


EXPORT PDEEPVIZ_RESULT deepviz_search(const char* api_key,
										const char* search_string, 
										int start_offset, 
										int elements){

	PDEEPVIZ_RESULT	result = NULL;
	void*			responseOut = NULL;
	size_t			responseOutLen = 0;
	json_t			*jsonObj = NULL;
	json_t			*jsonSet = NULL;
	char			*jsonRequestString = NULL;
	size_t			index;
	json_t			*value;
	char			*retMsg = NULL;
	deepviz_bool	bRet = deepviz_false;
	char			statusCode[DEEPVIZ_STATUS_CODE_MAX_LEN] = { 0 };
	char			tmpStr[100] = {0};
#ifdef _WIN32
	char			HTTPheader[DEEPVIZ_HTTP_HEADER_MAX_LEN] = { 0 };
#endif

	retMsg = (char*)malloc(DEEPVIZ_ERROR_MAX_LEN);
	if (!retMsg){
		return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, NULL);
	}

#if !defined(_WIN32) && !defined(__linux__)
	/* TODO */
	sprintf(retMsg, "Platform not supported");
	return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, retMsg);
#endif

	if (!api_key || !search_string){
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Invalid or missing parameters. Please try again!");
		return deepviz_result_init(DEEPVIZ_STATUS_INPUT_ERROR, retMsg);
	}

	/* Build SEARCH json request */

	jsonSet = json_array();
	deepviz_sprintf(tmpStr, 100, "start=%d", start_offset);
	json_array_append_new(jsonSet, json_string(tmpStr));
	deepviz_sprintf(tmpStr, 100, "rows=%d", elements);
	json_array_append_new(jsonSet, json_string(tmpStr));

	jsonObj = json_pack("{ssssso}",
						"api_key", api_key,
						"string", search_string,
						"result_set", jsonSet);

	/* Dump JSON string */
	jsonRequestString = json_dumps(jsonObj, 0);

	json_array_foreach(jsonSet, index, value){	json_decref(value);	}
	json_decref(jsonSet);
	json_decref(jsonObj);

	if (!jsonRequestString){
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Error creating HTTP request");
		return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, retMsg);
	}

#ifdef _WIN32
/* Windows */

	sprintf_s(HTTPheader, DEEPVIZ_HTTP_HEADER_MAX_LEN, "%s\r\n%s\r\n%s\r\n", DEEPVIZ_HTTP_HEADER_CTJ, DEEPVIZ_HTTP_HEADER_A, DEEPVIZ_HTTP_HEADER_AE);

	/* Send HTTP request */
	bRet = win_sendHTTPrequest( DEEPVIZ_SERVER,
								URL_INTEL_SEARCH,
								INTERNET_DEFAULT_HTTPS_PORT,
								HTTPheader,
								INTERNET_FLAG_SECURE,
								jsonRequestString,
								strlen(jsonRequestString),
								statusCode,
								DEEPVIZ_STATUS_CODE_MAX_LEN,
								&responseOut,
								&responseOutLen,
								retMsg);

#elif defined(__linux__)
/* Linux */

	bRet = linux_sendHTTPrequest(	DEEPVIZ_SERVER,
									URL_INTEL_SEARCH,
									jsonRequestString,
									statusCode,
									DEEPVIZ_STATUS_CODE_MAX_LEN,
									&responseOut,
									&responseOutLen,
									retMsg);

#endif

	free(jsonRequestString);

	if (bRet == deepviz_false){
		/* Network Error */
		if (responseOut) free(responseOut);
		return deepviz_result_init(DEEPVIZ_STATUS_NETWORK_ERROR, retMsg);
	}

	if (responseOutLen == 0){
		/* Empty response */
		if (responseOut) free(responseOut);
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "HTTP empty response");
		return deepviz_result_init(DEEPVIZ_STATUS_NETWORK_ERROR, retMsg);
	}

	free(retMsg);

	/* Parse API response and build DEEPVIZ_RESULT return value */
	result = parse_deepviz_response(statusCode, responseOut, responseOutLen);

	if (responseOut) free(responseOut);

	return result;

}


EXPORT PDEEPVIZ_RESULT deepviz_advanced_search(const char* api_key,
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
												int never_seen,
												const char* time_delta,
												const char* ip_range,
												PDEEPVIZ_LIST domain,
												int start_offset,
												int elements){
	
	PDEEPVIZ_RESULT	result;
	void*			responseOut = NULL;
	size_t			responseOutLen = 0;
	json_t			*jsonObj = NULL;
	json_t			*jsonSimHash = NULL;
	json_t			*jsonCreatedFiles = NULL;
	json_t			*jsonImpHash = NULL;
	json_t			*jsonUrl = NULL;
	json_t			*jsonStrings = NULL;
	json_t			*jsonIp = NULL;
	json_t			*jsonAsn = NULL;
	json_t			*jsonRules = NULL;
	json_t			*jsonCountry = NULL;
	json_t			*jsonDomain = NULL;
	json_t			*jsonSet = NULL;
	char			*jsonRequestString = NULL;
	size_t			index;
	json_t			*value;
	char			*retMsg = NULL;
	deepviz_bool	bRet = deepviz_false;
	size_t			i;
	char			statusCode[DEEPVIZ_STATUS_CODE_MAX_LEN] = { 0 };
	char			tmpStr[100] = { 0 };
#ifdef _WIN32
	char			HTTPheader[DEEPVIZ_HTTP_HEADER_MAX_LEN] = { 0 };
#endif

	retMsg = (char*)malloc(DEEPVIZ_ERROR_MAX_LEN);
	if (!retMsg){
		return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, NULL);
	}

#if !defined(_WIN32) && !defined(__linux__)
	/* TODO */
	sprintf(retMsg, "Platform not supported");
	return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, retMsg);
#endif

	if (!api_key){
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Invalid or missing parameters. Please try again!");
		return deepviz_result_init(DEEPVIZ_STATUS_INPUT_ERROR, retMsg);
	}

	/* Build ADVANCED SEARCH json request */

	/* Build result set array */
	jsonSet = json_array();
	deepviz_sprintf(tmpStr, 100, "start=%d", start_offset);
	json_array_append_new(jsonSet, json_string(tmpStr));
	deepviz_sprintf(tmpStr, 100,"rows=%d", elements);
	json_array_append_new(jsonSet, json_string(tmpStr));

	/* Build base json request */
	jsonObj = json_pack("{ssso}",
						"api_key", api_key,
						"result_set", jsonSet);

	/* Append "sim_hash" list */
	jsonSimHash = json_array();
	if (sim_hash){
		for (i = 0; i < sim_hash->maxEntryNumber; i++){
			if (sim_hash->entry[i][0]){
				json_array_append_new(jsonSimHash, json_string(sim_hash->entry[i]));
			}
		}
		if (json_array_size(jsonSimHash) > 0){
			/* Append list to JSON request */
			json_object_set_new(jsonObj, "sim_hash", jsonSimHash);
		}
	}

	/* Append "created_files" list */
	jsonCreatedFiles = json_array();
	if (created_files){
		for (i = 0; i < created_files->maxEntryNumber; i++){
			if (created_files->entry[i][0]){
				json_array_append_new(jsonCreatedFiles, json_string(created_files->entry[i]));
			}
		}
		if (json_array_size(jsonCreatedFiles) > 0){
			/* Append list to JSON request */
			json_object_set_new(jsonObj, "created_files", jsonCreatedFiles);
		}
	}

	/* Append "imp_hash" list */
	jsonImpHash = json_array();
	if (imp_hash){
		for (i = 0; i < imp_hash->maxEntryNumber; i++){
			if (imp_hash->entry[i][0]){
				json_array_append_new(jsonImpHash, json_string(imp_hash->entry[i]));
			}
		}
		if (json_array_size(jsonImpHash) > 0){
			/* Append list to JSON request */
			json_object_set_new(jsonObj, "imp_hash", jsonImpHash);
		}
	}

	/* Append "url" list */
	jsonUrl = json_array();
	if (url){
		for (i = 0; i < url->maxEntryNumber; i++){
			if (url->entry[i][0]){
				json_array_append_new(jsonUrl, json_string(url->entry[i]));
			}
		}
		if (json_array_size(jsonUrl) > 0){
			/* Append list to JSON request */
			json_object_set_new(jsonObj, "url", jsonUrl);
		}
	}

	/* Append "strings" list */
	jsonStrings = json_array();
	if (strings){
		for (i = 0; i < strings->maxEntryNumber; i++){
			if (strings->entry[i][0]){
				json_array_append_new(jsonStrings, json_string(strings->entry[i]));
			}
		}
		if (json_array_size(jsonStrings) > 0){
			/* Append list to JSON request */
			json_object_set_new(jsonObj, "strings", jsonStrings);
		}
	}

	/* Append "ip" list */
	jsonIp = json_array();
	if (ip){
		for (i = 0; i < ip->maxEntryNumber; i++){
			if (ip->entry[i][0]){
				json_array_append_new(jsonIp, json_string(ip->entry[i]));
			}
		}
		if (json_array_size(jsonIp) > 0){
			/* Append list to JSON request */
			json_object_set_new(jsonObj, "ip", jsonIp);
		}
	}

	/* Append "asn" list */
	jsonAsn = json_array();
	if (asn){
		for (i = 0; i < asn->maxEntryNumber; i++){
			if (asn->entry[i][0]){
				json_array_append_new(jsonAsn, json_string(asn->entry[i]));
			}
		}
		if (json_array_size(jsonAsn) > 0){
			/* Append list to JSON request */
			json_object_set_new(jsonObj, "asn", jsonAsn);
		}
	}

	/* Append "rules" list */
	jsonRules = json_array();
	if (rules){
		for (i = 0; i < rules->maxEntryNumber; i++){
			if (rules->entry[i][0]){
				json_array_append_new(jsonRules, json_string(rules->entry[i]));
			}
		}
		if (json_array_size(jsonRules) > 0){
			/* Append list to JSON request */
			json_object_set_new(jsonObj, "rules", jsonRules);
		}
	}

	/* Append "country" list */
	jsonCountry = json_array();
	if (country){
		for (i = 0; i < country->maxEntryNumber; i++){
			if (country->entry[i][0]){
				json_array_append_new(jsonCountry, json_string(country->entry[i]));
			}
		}
		if (json_array_size(jsonCountry) > 0){
			/* Append list to JSON request */
			json_object_set_new(jsonObj, "country", jsonCountry);
		}
	}

	/* Append "domain" list */
	jsonDomain = json_array();
	if (domain){
		for (i = 0; i < domain->maxEntryNumber; i++){
			if (domain->entry[i][0]){
				json_array_append_new(jsonDomain, json_string(domain->entry[i]));
			}
		}
		if (json_array_size(jsonDomain) > 0){
			/* Append list to JSON request */
			json_object_set_new(jsonObj, "domain", jsonDomain);
		}
	}

	/* Append "classification" string */
	if (classification){
		json_object_set_new(jsonObj, "classification", json_string(classification));
	}

	/* Append "never_seen" string */
	json_object_set_new(jsonObj, "never_seen", json_string( never_seen == deepviz_true ? "true" : "false"));
	
	/* Append "time_delta" string */
	if (time_delta){
		json_object_set_new(jsonObj, "time_delta", json_string(time_delta));
	}

	/* Append "ip_range" string */
	if (ip_range){
		json_object_set_new(jsonObj, "ip_range", json_string(ip_range));
	}

	/* Dump JSON string */
	jsonRequestString = json_dumps(jsonObj, 0);

	json_array_foreach(jsonSet, index, value){	json_decref(value); }
	json_decref(jsonSet);
	json_decref(jsonSimHash);
	json_decref(jsonCreatedFiles);
	json_decref(jsonImpHash);
	json_decref(jsonUrl);
	json_decref(jsonStrings);
	json_decref(jsonIp);
	json_decref(jsonAsn);
	json_decref(jsonRules);
	json_decref(jsonCountry);
	json_decref(jsonDomain);
	json_decref(jsonObj);

	if (!jsonRequestString){
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Error creating HTTP request");
		return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, retMsg);
	}

#ifdef _WIN32
/* Windows */

	sprintf_s(HTTPheader, DEEPVIZ_HTTP_HEADER_MAX_LEN, "%s\r\n%s\r\n%s\r\n", DEEPVIZ_HTTP_HEADER_CTJ, DEEPVIZ_HTTP_HEADER_A, DEEPVIZ_HTTP_HEADER_AE);

	/* Send HTTP request */
	bRet = win_sendHTTPrequest( DEEPVIZ_SERVER,
								URL_INTEL_SEARCH_ADVANCED,
								INTERNET_DEFAULT_HTTPS_PORT,
								HTTPheader,
								INTERNET_FLAG_SECURE,
								jsonRequestString,
								strlen(jsonRequestString),
								statusCode,
								DEEPVIZ_STATUS_CODE_MAX_LEN,
								&responseOut,
								&responseOutLen,
								retMsg);

#elif defined(__linux__)
/* Linux */

	bRet = linux_sendHTTPrequest(	DEEPVIZ_SERVER,
									URL_INTEL_SEARCH_ADVANCED,
									jsonRequestString,
									statusCode,
									DEEPVIZ_STATUS_CODE_MAX_LEN,
									&responseOut,
									&responseOutLen,
									retMsg);

#endif

	free(jsonRequestString);

	if (bRet == deepviz_false){
		/* Network Error */
		if (responseOut) free(responseOut);
		return deepviz_result_init(DEEPVIZ_STATUS_NETWORK_ERROR, retMsg);
	}

	free(retMsg);

	/* Parse API response and build DEEPVIZ_RESULT return value */
	result = parse_deepviz_response(statusCode, responseOut, responseOutLen);

	if (responseOut) free(responseOut);

	return result;

}