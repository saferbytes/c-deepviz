/*
* Copyright (c) 2016 Saferbytes s.r.l.s.
*
* You can redistribute it and/or modify it under the terms of the MIT license. 
* See LICENSE for details.
*/

#include "c-deepviz.h"
#include "c-deepviz_private.h"


EXPORT void	 deepviz_result_free(PDEEPVIZ_RESULT *result){

    if (!result){
        return;
    }

    if ((*result)->msg) 
        free((*result)->msg);

    free(*result);

    (*result) = NULL;

}


EXPORT PDEEPVIZ_LIST deepviz_list_init(size_t maxEntryNumber){

    PDEEPVIZ_LIST	list = NULL;

    if (maxEntryNumber == 0){
        return NULL;
    }

    list = (PDEEPVIZ_LIST)malloc(sizeof(DEEPVIZ_LIST) + (maxEntryNumber * DEEPVIZ_ENTRY_MAX_LEN));
    if (list){
        memset(list, 0, sizeof(DEEPVIZ_LIST) + (maxEntryNumber * DEEPVIZ_ENTRY_MAX_LEN));
        list->maxEntryNumber = maxEntryNumber;
    }

    return list;

}


EXPORT deepviz_bool deepviz_list_add(PDEEPVIZ_LIST list,
                                     const char* newEntry){

    size_t i = 0;

    if (!list || !newEntry){
        return deepviz_false;
    }

    /* Check for filter string length */
    if (strlen(newEntry) >= DEEPVIZ_ENTRY_MAX_LEN){
        return deepviz_false;
    }

    for (i = 0; i < list->maxEntryNumber; i++){
        /* Search for a free slot */
        if (list->entry[i][0] == '\0'){
            strncpy(list->entry[i], newEntry, strlen(newEntry));
            return deepviz_true;
        }
    }

    /* No space left on filter struct */
    return deepviz_false;

}


EXPORT void deepviz_list_free(PDEEPVIZ_LIST *list){

    if (*list){
        free(*list);
        (*list) = NULL;
    }

}


/* ====================== c-deepviz private functions ====================== */


int dvz_vsnprintf(char *outBuf, size_t size, const char *format, va_list ap){

    int count = -1;

    if (size > 0){
#ifdef _WIN32
        count = vsnprintf_s(outBuf, size, _TRUNCATE, format, ap);
#elif defined(__linux__)
        count = vsnprintf(outBuf, size, format, ap);
#endif
    }

    return count;
}


int deepviz_sprintf(char *outBuf, size_t size, const char *format, ...){

    int         count = -1;
    va_list     ap;

    memset(outBuf, 0, size);

    va_start(ap, format);
    count = dvz_vsnprintf(outBuf, size, format, ap);
    va_end(ap);

    return count;
}


PDEEPVIZ_RESULT parse_deepviz_response(const char* statusCode, void* response, size_t responseLen){

    json_t					*jsonObj = NULL;
    json_t					*jsonData = NULL;
    json_error_t			jsonError;
    DEEPVIZ_RESULT_STATUS	currStatus;
    char			        *retMsg = NULL;

    retMsg = (char*)malloc(DEEPVIZ_ERROR_MAX_LEN);
    if (!retMsg){
        return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, NULL);
    }

    /* Check for processing requests */
    if (!strcmp(statusCode, "428")){
        /* Processing */
        deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Status: %s - Analysis is running", statusCode);
        return deepviz_result_init(DEEPVIZ_STATUS_PROCESSING, retMsg);
    }

    if (responseLen == 0){
        /* Empty response */
        deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "HTTP empty response");
        return deepviz_result_init(DEEPVIZ_STATUS_NETWORK_ERROR, retMsg);
    }

    /* Load response JSON */
    jsonObj = json_loads((char*)response, responseLen, &jsonError);

    /* Check status code */
    if (strcmp(statusCode, "200")){

        /* Check response JSON */
        if (!jsonObj){
            deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Error loading Deepviz response: %s", statusCode);
            return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, retMsg);
        }

        /* Get "errmsg" string from JSON response */
        jsonData = json_object_get(jsonObj, "errmsg");
        if (!jsonData){
            /* Error parsing HTTP response */
            json_decref(jsonObj);
            deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Error while connecting to Deepviz: %s", statusCode);
            return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, retMsg);
        }

        if (statusCode[0] == '4'){
            /* 4XX errors */
            currStatus = DEEPVIZ_STATUS_CLIENT_ERROR;
        }
        else if (statusCode[0] == '5'){
            /* 5XX errors */
            currStatus = DEEPVIZ_STATUS_SERVER_ERROR;
        }
        else{
            currStatus = DEEPVIZ_STATUS_INTERNAL_ERROR;
        }

        deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Error: %s - %s", statusCode, json_string_value(jsonData));
        json_decref(jsonObj);

        return deepviz_result_init(currStatus, retMsg);
    }

    /* Check response JSON */
    if (!jsonObj){
        /* Error parsing HTTP response */
        if (jsonError.text){
            deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Error parsing HTTP response: %s", jsonError.text);
        }
        else{
            deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Error parsing HTTP response");
        }

        return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, retMsg);
    }

    /* Get response JSON data object */
    jsonData = json_object_get(jsonObj, "data");
    if (!jsonData){
        deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Error parsing HTTP response");
        json_decref(jsonObj);
        return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, retMsg);
    }

    free(retMsg);
    retMsg = NULL;

    /* Convert JSON object data to string */
    retMsg = json_dumps(jsonData, 0);

    /* Free response object */
    json_decref(jsonObj);

    return deepviz_result_init(DEEPVIZ_STATUS_SUCCESS, retMsg);

}


PDEEPVIZ_RESULT deepviz_result_init(DEEPVIZ_RESULT_STATUS status, char* msg){

    PDEEPVIZ_RESULT result;

    result = (PDEEPVIZ_RESULT)malloc(sizeof(DEEPVIZ_RESULT));
    if (!result){
        return NULL;
    }

    result->status = status;
    result->msg = msg;

    return result;

}

#ifdef _WIN32
/* Microsoft */

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
                                    char* errorMsg){

    HINTERNET       hOpen = NULL;
    HINTERNET       hConnect = NULL;
    HINTERNET       hRequest = NULL;
    DWORD           numberOfBytes = 512;
    BYTE            data[512];
    PVOID			tmpData = NULL;
    BOOL            decoding = TRUE;
    DWORD           rec_timeout = 3600000;

    hOpen = InternetOpenA(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (hOpen == NULL){
        sprintf_s(errorMsg, DEEPVIZ_ERROR_MAX_LEN, "Error opening connection: %d\n", GetLastError());
        return deepviz_false;
    }

    hConnect = InternetConnectA(hOpen, httpServerName, (INTERNET_PORT)connectionFlags, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (hConnect == NULL){
        sprintf_s(errorMsg, DEEPVIZ_ERROR_MAX_LEN, "Error while connecting to Deepviz: %d\n", GetLastError());
        InternetCloseHandle(hOpen);
        return deepviz_false;
    }

    hRequest = HttpOpenRequestA(hConnect, "POST", httpPage, NULL, NULL, NULL, requestFlags, 0);
    if (hRequest == NULL){
        sprintf_s(errorMsg, DEEPVIZ_ERROR_MAX_LEN, "Error opening HTTP request: %d\n", GetLastError());
        InternetCloseHandle(hOpen);
        InternetCloseHandle(hConnect);
        return deepviz_false;
    }

    /* Set HTTP request timeout to 1 hr */
    InternetSetOptionW(hRequest, INTERNET_OPTION_CONNECT_TIMEOUT, &rec_timeout, sizeof(rec_timeout));
    InternetSetOptionW(hRequest, INTERNET_OPTION_RECEIVE_TIMEOUT, &rec_timeout, sizeof(rec_timeout));

    /* Enable HTTP reply buffer decoding */
    InternetSetOptionA(hRequest, INTERNET_OPTION_HTTP_DECODING, &decoding, sizeof(decoding));

    if (!HttpSendRequestA(hRequest, HTTPheader, (DWORD)strlen(HTTPheader), requestBuffer, requestBufferLen)){
        sprintf_s(errorMsg, DEEPVIZ_ERROR_MAX_LEN, "Error sending HTTP request: %d\n", GetLastError());
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hOpen);
        return deepviz_false;
    }

    numberOfBytes = statusCodeOutLen;

    if (!HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE, statusCodeOut, &numberOfBytes, 0)){
        sprintf_s(errorMsg, DEEPVIZ_ERROR_MAX_LEN, "Error getting request info: %d\n", GetLastError());
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hOpen);
        return deepviz_false;
    }

    /* Read HTTP response */
    if (responseOut){

        (*responseOutLen) = 0;

        do{
            RtlZeroMemory(data, 512);
            numberOfBytes = 0;

            /* Read HTTP data */
            if (InternetReadFile(hRequest, (PVOID)data, 512, &numberOfBytes)){

                if (numberOfBytes == 0){
                    break;
                }

                if ((*responseOutLen) == 0){	
                /* First iteration */

                    (*responseOut) = malloc(numberOfBytes + 1);
                    if (!(*responseOut)){
                        break;
                    }
                    RtlZeroMemory((*responseOut), numberOfBytes + 1);

                    memcpy_s((*responseOut), numberOfBytes + 1, data, numberOfBytes);
                }
                else {							
                /* Update buffer */

                    tmpData = malloc((*responseOutLen) + numberOfBytes + 1);
                    if (!tmpData){
                        break;
                    }
                    RtlZeroMemory(tmpData, (*responseOutLen) + numberOfBytes + 1);

                    memcpy_s(tmpData, (*responseOutLen) + numberOfBytes, (*responseOut), (*responseOutLen));
                    memcpy_s((PVOID)((ULONG_PTR)tmpData + (*responseOutLen)), (*responseOutLen) + numberOfBytes + 1, data, numberOfBytes);

                    free((*responseOut));
                    (*responseOut) = tmpData;
                }

                (*responseOutLen) += numberOfBytes;

            }
            else{
                sprintf_s(errorMsg, DEEPVIZ_ERROR_MAX_LEN, "Error InternetReadFile: %d\n", GetLastError());
                InternetCloseHandle(hRequest);
                InternetCloseHandle(hConnect);
                InternetCloseHandle(hOpen);
                return deepviz_false;
            }

        } while (numberOfBytes != 0);
    }

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hOpen);
    return deepviz_true;

}

#elif defined(__linux__)
/* Linux */

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp){

    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    mem->memory = realloc(mem->memory, mem->size + realsize + 1);
    if(mem->memory == NULL) {
        /* out of memory! */
        return 0;
    }
    
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

deepviz_bool linux_sendHTTPrequest(	  const char* serverName,
                                      const char* httpPage,
                                      const char* requestBuffer,
                                      char* statusCodeOut,
                                      size_t statusCodeOutLen,
                                      void** responseOut,
                                      size_t *responseOutLen,
                                      char* errorMsg){

    CURL 		        *curl;
    CURLcode 	        res;
    char		        requestString[1024];
    struct curl_slist   *chunk = NULL;
    struct MemoryStruct data;
    long		        statusCode;

    memset(requestString, 0, 1024);

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();
    if (!curl) {
        snprintf(errorMsg, DEEPVIZ_ERROR_MAX_LEN, "Error while connecting to Deepviz\n");
        return deepviz_false;
    }

    data.memory = malloc(1);  	/* will be grown as needed by realloc above */
    data.size = 0;    			/* no data at this point */
    
    /* Build URL */
    snprintf(requestString, 1024, "https://%s/%s", serverName, httpPage);
    curl_easy_setopt(curl, CURLOPT_URL, requestString);

    /* Set HTTP headers */
    chunk = curl_slist_append(chunk, "Accept:");
    chunk = curl_slist_append(chunk, DEEPVIZ_HTTP_HEADER_CTJ);
    chunk = curl_slist_append(chunk, DEEPVIZ_HTTP_HEADER_A);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

    /* Save Response data buffer */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&data);

    /* Set POST data */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, requestBuffer);

    /*curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);*/

    /* Perform the request */
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        /* Error during request */

        free(data.memory);
        curl_easy_cleanup(curl);

        snprintf(errorMsg, DEEPVIZ_ERROR_MAX_LEN, "Error while connecting to Deepviz: %s\n", curl_easy_strerror(res));
        return deepviz_false;
    }

    /* Save status code */
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &statusCode);
    snprintf(statusCodeOut, statusCodeOutLen, "%ld", statusCode);

    /* Save response data */
    (*responseOut) = malloc(data.size + 1);
    if((*responseOut)){
        memset((*responseOut), 0, data.size + 1 );
        (*responseOutLen) = data.size;
        memcpy((*responseOut), data.memory, data.size);
    }

    free(data.memory);

    /* Curl cleanup */
    curl_easy_cleanup(curl);
    return deepviz_true;

}

deepviz_bool linux_sendHTTPrequestMultipart(	const char* serverName,
                                                const char* httpPage,
                                                const char* apikey,
                                                const char* filePath,
                                                char* statusCodeOut,
                                                size_t statusCodeOutLen,
                                                void** responseOut,
                                                size_t *responseOutLen,
                                                char* errorMsg){

    CURL 		            *curl;
    CURLcode 	            res;
    char		            requestString[1024];
    struct 		            MemoryStruct data;
    long		            statusCode;
    struct curl_httppost    *formpost = NULL;
    struct curl_httppost    *lastptr = NULL;
    struct curl_slist       *headerlist = NULL;

    memset(requestString, 0, 1024);

    curl_global_init(CURL_GLOBAL_ALL);

    /* Build multipart form post */
    curl_formadd(&formpost,
                 &lastptr,
                 CURLFORM_COPYNAME, "api_key",
                 CURLFORM_COPYCONTENTS, apikey,
                 CURLFORM_END);

    curl_formadd(&formpost,
                 &lastptr,
                 CURLFORM_COPYNAME, "source",
                 CURLFORM_COPYCONTENTS, DEEPVIZ_MULTIPART_SOURCE,
                 CURLFORM_END);

    curl_formadd(&formpost,
                 &lastptr,
                 CURLFORM_COPYNAME, "file",
                 CURLFORM_FILE, filePath,
                 CURLFORM_CONTENTTYPE, "application/x-msdownload",
                 CURLFORM_END);

    curl = curl_easy_init();
    if (!curl) {
        snprintf(errorMsg, DEEPVIZ_ERROR_MAX_LEN, "Error while connecting to Deepviz\n");
        return deepviz_false;
    }
    
    data.memory = malloc(1);  	/* will be grown as needed by realloc above */
    data.size = 0;    			/* no data at this point */

    /* Build URL */
    snprintf(requestString, 1024, "https://%s/%s", serverName, httpPage);
    curl_easy_setopt(curl, CURLOPT_URL, requestString);

    /* Set HTTP headers */
    headerlist = curl_slist_append(headerlist, "Accept:");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);

    /* Set POST data */
    curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);

    /* Save Response data buffer */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&data);
    
    /* Perform the request */
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        /* Error during request */

        free(data.memory);
        curl_easy_cleanup(curl);
        curl_formfree(formpost);
        curl_slist_free_all (headerlist);

        snprintf(errorMsg, DEEPVIZ_ERROR_MAX_LEN, "Error while connecting to Deepviz: %s\n", curl_easy_strerror(res));
        return deepviz_false;
    }

    /* Save status code */
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &statusCode);
    snprintf(statusCodeOut, statusCodeOutLen, "%ld", statusCode);

    /* Save response data */
    (*responseOut) = malloc(data.size + 1);
    if((*responseOut)){
        memset((*responseOut), 0, data.size + 1 );
        (*responseOutLen) = data.size;
        memcpy((*responseOut), data.memory, data.size);
    }

    free(data.memory);

    /* Curl cleanup */
    curl_easy_cleanup(curl);
    curl_formfree(formpost);
    curl_slist_free_all (headerlist);

    return deepviz_true;

}


#endif