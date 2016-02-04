/*
* Copyright (c) 2016 Saferbytes s.r.l.s.
*
* You can redistribute it and/or modify it under the terms of the MIT license.
* See LICENSE for details.
*/

#include "c-deepviz.h"
#include "c-deepviz_private.h"


EXPORT PDEEPVIZ_RESULT deepviz_upload_sample(	const char* api_key,
												const char* path){

	PDEEPVIZ_RESULT		result = NULL;
	void*			    responseOut = NULL;
	size_t			    responseOutLen = 0;
	deepviz_bool		bRet = deepviz_false;
	char			    statusCode[DEEPVIZ_STATUS_CODE_MAX_LEN] = { 0 };
	char		    	*retMsg;
	FILE		    	*file;
#ifdef _WIN32
	long		    	fileSize;
	void*		    	fileBuffer;
	char			    HTTPheader[DEEPVIZ_HTTP_HEADER_MAX_LEN] = { 0 };
	size_t			    firstHTTPpartLen;
	char			    endHTTP[100] = { 0 };
	size_t		    	res;
	char		    	*request = NULL;
	char				*fileName = NULL;
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

	if (!api_key || !path){
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Invalid or missing parameters. Please try again!");
		return deepviz_result_init(DEEPVIZ_STATUS_INPUT_ERROR, retMsg);
	}

	/* Open file */
	file = fopen(path, "rb");
	if (!file){
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Unable to open file. errno: %d", errno);
		return deepviz_result_init(DEEPVIZ_STATUS_INPUT_ERROR, retMsg);
	}

#ifdef _WIN32
/* Windows */

	/* Obtain file size */
	fseek(file, 0, SEEK_END);
	fileSize = ftell(file);
	rewind(file);

	/* Allocate memory to contain the file */
	fileBuffer = malloc(fileSize);
	if (!fileBuffer){
		fclose(file);
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Memory allocation error");
		return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, retMsg);
	}

	/* Read file buffer */
	res = fread(fileBuffer, 1, fileSize, file);
	if (res != (size_t)fileSize) {
		fclose(file);
		free(fileBuffer);
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Unable to read file. errno: %d", errno);
		return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, retMsg);
	}

	fclose(file);

	/* Build the first part of the multipart HTTP payload */
	request = (char*)malloc(fileSize + DEEPVIZ_PAYLOAD_MAX_LEN);			// size of file + MAX size of HTTP header
	if (!request){
		free(fileBuffer);
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Memory allocation error");
		return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, retMsg);
	}

	memset(request, 0, fileSize + DEEPVIZ_PAYLOAD_MAX_LEN);

	/* Get file name from path */
	fileName = (char*)malloc(strlen(path));
	if (!fileName){
		free(fileBuffer);
		free(request);
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Memory allocation error");
		return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, retMsg);
	}

	memset(fileName, 0, strlen(path));
	_splitpath_s(path, NULL, 0, NULL, 0, fileName, strlen(path), NULL, 0);

	/* Create first part of the HTTP payload */
	sprintf_s(	request,
				fileSize + DEEPVIZ_PAYLOAD_MAX_LEN,
				"--%s\r\nContent-Disposition: form-data; name=\"source\"\r\n\r\n%s\r\n"
				"--%s\r\nContent-Disposition: form-data; name=\"api_key\"\r\n\r\n%s\r\n"
				"--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
				"Content-Type: application/x-msdownload\r\n\r\n",
				DEEPVIZ_BOUNDARY, DEEPVIZ_MULTIPART_SOURCE,
				DEEPVIZ_BOUNDARY, api_key,
				DEEPVIZ_BOUNDARY, fileName);

	firstHTTPpartLen = strlen(request);

	/* Check buffer size */
	if (firstHTTPpartLen >= DEEPVIZ_PAYLOAD_MAX_LEN){
		free(request);
		free(fileBuffer);
		free(fileName);
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Memory allocation error");
		return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, retMsg);
	}

	/* Append the file buffer to the request */
	memcpy_s(request + firstHTTPpartLen,
		fileSize + DEEPVIZ_PAYLOAD_MAX_LEN - firstHTTPpartLen,
		(PVOID)fileBuffer,
		fileSize);

	/* Append last part of the HTTP payload */
	sprintf_s(endHTTP, 100, "\r\n--%s--\r\n\r\n", DEEPVIZ_BOUNDARY);
	memcpy_s(request + firstHTTPpartLen + fileSize,
			DEEPVIZ_PAYLOAD_MAX_LEN - firstHTTPpartLen,
			(PVOID)endHTTP,
			strlen(endHTTP));


	sprintf_s(HTTPheader, DEEPVIZ_HTTP_HEADER_MAX_LEN, "%s; boundary=%s\r\n", DEEPVIZ_HTTP_HEADER_CTM, DEEPVIZ_BOUNDARY);

	/* Send HTTP request */
	bRet = win_sendHTTPrequest( DEEPVIZ_SERVER,
								URL_UPLOAD_SAMPLE,
								INTERNET_DEFAULT_HTTPS_PORT,
								HTTPheader,
								INTERNET_FLAG_SECURE,
								request,
								firstHTTPpartLen + fileSize + strlen(endHTTP),
								statusCode,
								DEEPVIZ_STATUS_CODE_MAX_LEN,
								&responseOut,
								&responseOutLen,
								retMsg);

	free(fileBuffer);
	free(request);
	free(fileName);

#elif defined(__linux__)
/* Linux */

	/* Close file, will be read by CURL lib */
	fclose(file);

	bRet = linux_sendHTTPrequestMultipart(	DEEPVIZ_SERVER,
											URL_UPLOAD_SAMPLE,
											api_key,
											path,
											statusCode,
											DEEPVIZ_STATUS_CODE_MAX_LEN,
											&responseOut,
											&responseOutLen,
											retMsg);

#endif

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


EXPORT PDEEPVIZ_RESULT deepviz_upload_folder(	const char* api_key,
												const char* folder){

	char				*retMsg = NULL;
	PDEEPVIZ_RESULT		result = NULL;
	char                currPath[DEEPVIZ_FILEPATH_MAX_LEN] = { 0 };
#ifdef _WIN32
/* Windows */
	HANDLE				hFile;
	WIN32_FIND_DATAA	data;
	char*				tmpFolder = NULL;
#elif defined(__linux__)
/* Linux */
	DIR                 *dir;
	struct dirent       *entry;
	int                 len;
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

	if (!api_key || !folder){
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Invalid or missing parameters. Please try again!");
		return deepviz_result_init(DEEPVIZ_STATUS_INPUT_ERROR, retMsg);
	}

#ifdef _WIN32
	/* Windows */

	memset(&data, 0, sizeof(WIN32_FIND_DATAA));

	tmpFolder = malloc(strlen(folder) + 10);
	if (!tmpFolder){
		sprintf_s(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Memory allocation error");
		return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, retMsg);
	}

	memset(tmpFolder, 0, strlen(folder) + 10);

	/* Add "\*" */
	sprintf_s(tmpFolder, strlen(folder) + 10, "%s\\*", folder);

	hFile = FindFirstFileA(tmpFolder, &data);
	if (hFile == INVALID_HANDLE_VALUE) {
		sprintf_s(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Invalid folder. Error %d", GetLastError());
		return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, retMsg);
	}

	/* Remove "\*" */
	tmpFolder[strlen(tmpFolder) - 2] = 0;

	/* First file is always "." */
	while (FindNextFileA(hFile, &data)){

		if (strcmp("..", data.cFileName) && strcmp(".", data.cFileName)){

			if (strlen(tmpFolder) + strlen(data.cFileName) >= DEEPVIZ_FILEPATH_MAX_LEN){
				FindClose(hFile);
				free(tmpFolder);
				sprintf_s(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Invalid folder");
				return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, retMsg);
			}

			sprintf_s(currPath, DEEPVIZ_FILEPATH_MAX_LEN, "%s\\%s", tmpFolder, data.cFileName);

			if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY){
				/* Go to next folder */
				deepviz_upload_folder(api_key, currPath);
			}
			else {

				result = deepviz_upload_sample(api_key, currPath);
				if (result){

					/*printf("FILE: %s - STATUS: %d - MSG: %s\n", currPath, result->status, result->msg); */

					if (result->status != DEEPVIZ_STATUS_SUCCESS){
						sprintf_s(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Error uploading file \"%s\": %d - %s", currPath, result->status, result->msg);
						deepviz_result_free(result);
						FindClose(hFile);
						free(tmpFolder);
						return deepviz_result_init(DEEPVIZ_STATUS_INPUT_ERROR, retMsg);
					}

					deepviz_result_free(result);
				}
			}
		}
	}

	FindClose(hFile);
	free(tmpFolder);

#elif defined(__linux__)
	/* Linux */

	if (!(dir = opendir(folder))) {
		snprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Invalid folder");
		return deepviz_result_init(DEEPVIZ_STATUS_INPUT_ERROR, retMsg);
	}

	do {

		entry = readdir(dir);
		if (entry) {

			if (entry->d_type == DT_DIR) {

				len = snprintf(currPath, DEEPVIZ_FILEPATH_MAX_LEN, "%s/%s", folder, entry->d_name);
				currPath[len] = 0;

				if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
					/* Recursive call */
					deepviz_upload_folder(api_key, currPath);
				}

			}
			else {

				snprintf(currPath, DEEPVIZ_FILEPATH_MAX_LEN, "%s/%s", folder, entry->d_name);

				result = deepviz_upload_sample(api_key, currPath);
				if (result){

					/* printf("FILE: %s - STATUS: %d - MSG: %s\n", currPath, result->status, result->msg); */

					if (result->status != DEEPVIZ_STATUS_SUCCESS){
						snprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Error uploading file \"%s\": %d - %s", currPath, result->status, result->msg);
						deepviz_result_free(result);
						closedir(dir);
						return deepviz_result_init(DEEPVIZ_STATUS_INPUT_ERROR, retMsg);
					}

					deepviz_result_free(result);
				}
			}
		}

	} while (entry);

	closedir(dir);

#endif

	deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Folder uploaded to Deepviz successfully");
	return deepviz_result_init(DEEPVIZ_STATUS_SUCCESS, retMsg);

}


EXPORT PDEEPVIZ_RESULT deepviz_sample_download(	const char* md5,
												const char* api_key, 
												const char* path){

	void*				responseOut;
	char				statusCode[DEEPVIZ_STATUS_CODE_MAX_LEN] = { 0 };
	size_t				responseOutLen = 0;
	char				*retMsg = NULL;
	FILE				*file;
	char*				filePath = NULL;
	json_t				*jsonObj = NULL;
	json_t				*jsonData = NULL;
	json_error_t		jsonError;
	char				*jsonRequestString = NULL;
	deepviz_bool		bRet = deepviz_false;
#ifdef _WIN32
	char				HTTPheader[DEEPVIZ_HTTP_HEADER_MAX_LEN] = { 0 };
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

	if (!md5 || !api_key || !path){
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Invalid or missing parameters. Please try again!");
		return deepviz_result_init(DEEPVIZ_STATUS_INPUT_ERROR, retMsg);
	}

	filePath = (char*)malloc(strlen(path) + strlen(md5) + 2);
	if (!filePath){
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Memory allocation error");
		return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, retMsg);
	}

	/* Build final file path */
#ifdef _WIN32
	sprintf_s(filePath, strlen(path) + strlen(md5) + 2, "%s\\%s", path, md5);
#else
	snprintf(filePath, strlen(path) + strlen(md5) + 2, "%s/%s", path, md5);
#endif

	file = fopen(filePath, "wb");
	if (!file){
		free(filePath);
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Unable to create file. errno: %d", errno);
		return deepviz_result_init(DEEPVIZ_STATUS_INPUT_ERROR, retMsg);
	}

	/* Build JSON object */
	jsonObj = json_pack("{ssss}",
						"api_key", api_key,
						"md5", md5);

	/* Dump JSON string */
	jsonRequestString = json_dumps(jsonObj, 0);

	json_decref(jsonObj);

	if (!jsonRequestString){
		free(filePath);
		fclose(file);
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Error creating HTTP request");
		return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, retMsg);
	}

#ifdef _WIN32
	/* Windows */

	sprintf_s(HTTPheader, DEEPVIZ_HTTP_HEADER_MAX_LEN, "%s\r\n%s\r\n%s\r\n", DEEPVIZ_HTTP_HEADER_CTJ, DEEPVIZ_HTTP_HEADER_A, DEEPVIZ_HTTP_HEADER_AE);

	/* Send HTTP request */
	bRet = win_sendHTTPrequest( DEEPVIZ_SERVER,
								URL_DOWNLOAD_SAMPLE,
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
									URL_DOWNLOAD_SAMPLE,
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
		free(filePath);
		fclose(file);
		if (responseOut) free(responseOut);
		return deepviz_result_init(DEEPVIZ_STATUS_NETWORK_ERROR, retMsg);
	}

	if (responseOutLen == 0){
		/* Empty response */
		free(filePath);
		fclose(file);
		if (responseOut) free(responseOut);
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "HTTP empty response");
		return deepviz_result_init(DEEPVIZ_STATUS_NETWORK_ERROR, retMsg);
	}

	/* Check status code */
	if (strcmp(statusCode, "200")){

		free(filePath);
		fclose(file);

		/* Load response JSON */
		jsonObj = json_loads((char*)responseOut, responseOutLen, &jsonError);
		if (!jsonObj){
			if (responseOut) free(responseOut);
			deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Error while connecting to Deepviz: %s", statusCode);
			return deepviz_result_init(DEEPVIZ_STATUS_NETWORK_ERROR, retMsg);
		}

		/* Get "errmsg" string from JSON response */
		jsonData = json_object_get(jsonObj, "errmsg");
		if (!jsonData){
			/* Error parsing HTTP response */
			json_decref(jsonObj);
			if (responseOut) free(responseOut);
			deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Error while connecting to Deepviz: %s", statusCode);
			return deepviz_result_init(DEEPVIZ_STATUS_NETWORK_ERROR, retMsg);
		}

		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Error: %s - %s", statusCode, json_string_value(jsonData));
		json_decref(jsonObj);

		return deepviz_result_init(DEEPVIZ_STATUS_NETWORK_ERROR, retMsg);
	}

	/* Write sample file */
	if (!fwrite(responseOut, responseOutLen, 1, file)){
		free(filePath);
		fclose(file);
		if (responseOut) free(responseOut);
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Unable to save file. errno: %d", errno);
		return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, retMsg);
	}

	deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "File downloaded to: %s", filePath);

	free(filePath);
	fclose(file);
	if (responseOut) free(responseOut);

	return deepviz_result_init(DEEPVIZ_STATUS_SUCCESS, retMsg);

}


EXPORT PDEEPVIZ_RESULT deepviz_sample_result(	const char* md5,
												const char* api_key){

	PDEEPVIZ_RESULT		result = NULL;
	char				*retMsg = NULL;
	PDEEPVIZ_LIST		list = NULL;

	retMsg = (char*)malloc(DEEPVIZ_ERROR_MAX_LEN);
	if (!retMsg){
		return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, NULL);
	}

#if !defined(_WIN32) && !defined(__linux__)
	/* TODO */
	sprintf(retMsg, "Platform not supported");
	return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, retMsg);
#endif

	if (!md5 || !api_key){
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Invalid or missing parameters. Please try again!");
		return deepviz_result_init(DEEPVIZ_STATUS_INPUT_ERROR, retMsg);
	}

	/* Init filter struct */
	list = deepviz_list_init(1);
	if (!list){
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Internal Error");
		return deepviz_result_init(DEEPVIZ_STATUS_INTERNAL_ERROR, retMsg);
	}

	free(retMsg);

	/* Set "classification" filter */
	deepviz_list_add(list, "classification");

	/* Send API request */
	result = deepviz_sample_report(md5, api_key, list);

	deepviz_list_free(list);

	return result;

}


EXPORT PDEEPVIZ_RESULT deepviz_sample_report(	const char* md5,
												const char* api_key, 
												PDEEPVIZ_LIST filters){
	PDEEPVIZ_RESULT	result = NULL;
	void*			responseOut = NULL;
	size_t			responseOutLen = 0;
	json_t			*jsonObj = NULL;
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

	if (!md5 || !api_key){
		deepviz_sprintf(retMsg, DEEPVIZ_ERROR_MAX_LEN, "Invalid or missing parameters. Please try again!");
		return deepviz_result_init(DEEPVIZ_STATUS_INPUT_ERROR, retMsg);
	}

	/* Build SAMPLE REPORT json request */

	/* Build filter JSON array (if any) */
	if (filters){
		jsonFilters = json_array();
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

	jsonObj = json_pack("{ssss}",
						"api_key", api_key,
						"md5", md5);

	if (json_array_size(jsonFilters)){
		/* Filters provided, add to request */
		json_object_set_new(jsonObj, "output_filters", jsonFilters);
	}

	/* Dump JSON string */
	jsonRequestString = json_dumps(jsonObj, 0);

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
								URL_DOWNLOAD_REPORT,
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
									URL_DOWNLOAD_REPORT,
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



