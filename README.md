# c-deepviz

c-deepviz is a C library wrapper for deepviz.com REST APIs

## Supported platforms
- Windows
- Linux

## How to build

C-deepviz can be built using CMake (https://cmake.org/). Create a build directory for an out-of-tree build and run cmake (or ccmake, cmake-gui, or similar) to configure the project.
On linux systems c-deepviz uses libcurl (http://curl.haxx.se/libcurl/) to make HTTP requests. To build the project on linux you must install the libcurl developmets files.

##### Linux
To generate a Makefile on linux using CMake from the command line:

Debian / Ubuntu OS:

```bash
apt-get install cmake
apt-get install libcurl4-openssl-dev

mkdir build
cd build
cmake ..
```

Red Hat / Fedora / CentOS:

```bash
yum install cmake
yum install libcurl-devel

mkdir build
cd build
cmake ..
```

##### Windows
To create a Visual Studio project files using CMake from the command line:

```bash
md build
cd build
cmake ..
```

## Usage 

To use Deepviz API SDK you will need an API key. You can get it by
subscribing the service for free at https://account.deepviz.com/register/

## SDK API examples

#### Sandbox 

To upload a sample:

```C++
#include "c-deepviz.h"

...
PDEEPVIZ_RESULT result = NULL;
const char* apikey = "--------------------------your-apikey---------------------------";

result = deepviz_upload_sample(apikey, "<sample_file_path>");
if (result){
	printf("STATUS: %d - MSG: %s\n", result->status, result->msg);
}

deepviz_result_free(&result);
```

To upload a folder:

```C++
#include "c-deepviz.h"

...
PDEEPVIZ_RESULT result = NULL;
const char* apikey = "--------------------------your-apikey---------------------------";

result = deepviz_upload_folder(apikey, "<folder_path>");
if (result){
    printf("STATUS: %d - MSG: %s\n", result->status, result->msg);
}

deepviz_result_free(&result);
```

To download a sample:

```C++
#include "c-deepviz.h"

...
PDEEPVIZ_RESULT result = NULL;
const char* md5 = "-----------file-md5-------------";
const char* apikey = "--------------------------your-apikey---------------------------";

result = deepviz_sample_download(md5, apikey, "<download_folder_path>");
if (result){
	printf("STATUS: %d - MSG: %s\n", result->status, result->msg);
}

deepviz_result_free(&result);
```

To retrieve scan result of a specific MD5:

```C++
#include "c-deepviz.h"

...
PDEEPVIZ_RESULT result = NULL;
const char* md5 = "-----------file-md5-------------";
const char* apikey = "--------------------------your-apikey---------------------------";

result = deepviz_sample_result(md5, apikey);
if (result){
    if (result->status == DEEPVIZ_STATUS_SUCCESS){
		printf("JSON RESULT: %s\n", result->msg);
	}
	else{
		printf("ERROR CODE: %d - MSG: %s\n", result->status, result->msg);
	}
}

deepviz_result_free(&result);
```

To retrieve full scan report for a specific MD5:

```C++
#include "c-deepviz.h"

...
PDEEPVIZ_RESULT result = NULL;
const char* md5 = "-----------file-md5-------------";
const char* apikey = "--------------------------your-apikey---------------------------";

result = deepviz_sample_report(md5, apikey, NULL);
if (result){
	if (result->status == DEEPVIZ_STATUS_SUCCESS){
		printf("JSON RESULT: %s\n", result->msg);
	}
	else{
		printf("ERROR CODE: %d - MSG: %s\n", result->status, result->msg);
	}
}

deepviz_result_free(&result);
```

To retrieve only specific parts of the report of a specific MD5 scan:

```C++
#include "c-deepviz.h"

...
PDEEPVIZ_RESULT result = NULL;
PDEEPVIZ_LIST	filters = NULL;
const char* md5 = "-----------file-md5-------------";
const char* apikey = "--------------------------your-apikey---------------------------";

filters = deepviz_list_init(<number_of_filters>);
if (filters){

	deepviz_list_add(filters, "<deepviz_filter_1>");
	...
	deepviz_list_add(filters, "<deepviz_filter_n>");

	result = deepviz_sample_report(md5, apikey, filters);
	if (result){
		if (result->status == DEEPVIZ_STATUS_SUCCESS){
			printf("JSON RESULT: %s\n", result->msg);
		}
		else{
			printf("ERROR CODE: %d - MSG: %s\n", result->status, result->msg);
		}
	}

	deepviz_list_free(&filters);
	deepviz_result_free(&result);
}
```
#### Threat Intelligence

To retrieve intel data about one or more IPs:

```C++
#include "c-deepviz.h"

...
PDEEPVIZ_RESULT result = NULL;
PDEEPVIZ_LIST	ipList = NULL;
const char* apikey = "--------------------------your-apikey---------------------------";

ipList = deepviz_list_init(<number_of_IPs>);
if (ipList){

	deepviz_list_add(ipList, "<ip_address_1");
	...
	deepviz_list_add(ipList, "<ip_address_n");

	result = deepviz_ip_info(apikey, ipList, NULL, <deepviz_false/deepviz_true>);
	if (result){
		if (result->status == DEEPVIZ_STATUS_SUCCESS){
			printf("JSON RESULT: %s\n", result->msg);
		}
		else{
			printf("ERROR CODE: %d - MSG: %s\n", result->status, result->msg);
		}
	}

	deepviz_list_free(&ipList);
	deepviz_result_free(&result);
}
```

To retrieve intel data about one or more domains:

```C++
#include "c-deepviz.h"

...
PDEEPVIZ_RESULT result = NULL;
PDEEPVIZ_LIST	domainList = NULL;
PDEEPVIZ_LIST	filters = NULL;
const char* apikey = "--------------------------your-apikey---------------------------";

domainList = deepviz_list_init(<number_of_domains>);
filters = deepviz_list_init(<number_of_domain_filters>);
if (domainList && filters){

	deepviz_list_add(domainList, "<domain_1>");
	...
	deepviz_list_add(domainList, "<domain_n>");

	deepviz_list_add(filters, "<domain_filter_1>");	
	...
	deepviz_list_add(filters, "<domain_filter_n>");

	result = deepviz_domain_info(apikey, domainList, NULL, <deepviz_false/deepviz_true>, filters);
	if (result){
		if (result->status == DEEPVIZ_STATUS_SUCCESS){
			printf("JSON RESULT: %s\n", result->msg);
		}
		else{
			printf("ERROR CODE: %d - MSG: %s\n", result->status, result->msg);
		}
	}

	deepviz_list_free(&domainList);
	deepviz_list_free(&filters);
	deepviz_result_free(&result);
}
```

To retrieve newly registered domains in the last 7 days:

```C++
#include "c-deepviz.h"

...
PDEEPVIZ_RESULT result = NULL;
PDEEPVIZ_LIST	filters = NULL;
const char* apikey = "--------------------------your-apikey---------------------------";
const char* timeDelta = "7d";

filters = deepviz_list_init(<number_of_domain_filters>);
if (filters){

	deepviz_list_add(filters, "<domain_filter_1>");	
	...
	deepviz_list_add(filters, "<domain_filter_n>");

	result = deepviz_domain_info(apikey, NULL, timeDelta, <deepviz_false/deepviz_true>, filters);
	if (result){
		if (result->status == DEEPVIZ_STATUS_SUCCESS){
			printf("JSON RESULT: %s\n", result->msg);
		}
		else{
			printf("ERROR CODE: %d - MSG: %s\n", result->status, result->msg);
		}
	}

	deepviz_list_free(&filters);
	deepviz_result_free(&result);
}
```

To run generic search based on strings 
(find all IPs, domains, samples related to the searched keyword):

```C++
#include "c-deepviz.h"

...
PDEEPVIZ_RESULT result = NULL;
PDEEPVIZ_LIST	filters = NULL;
const char* apikey = "--------------------------your-apikey---------------------------";
const char* searchString = "<your_keyword>";
int result_set_start = 0;
int result_set_number_of_element = 100;

result = deepviz_search(api, searchString, result_set_start, result_set_number_of_element);
if (result){
	if (result->status == DEEPVIZ_STATUS_SUCCESS){
		printf("JSON RESULT: %s\n", result->msg);
	}
	else{
		printf("ERROR CODE: %d - MSG: %s\n", result->status, result->msg);
	}
}

deepviz_result_free(&result);
```

To run advanced search based on parameters
(find the first 100 samples md5 connecting to a domain and determined as malicious):

```C++
#include "c-deepviz.h"

...
PDEEPVIZ_RESULT result = NULL;
PDEEPVIZ_LIST	domainList = NULL;
const char* apikey = "--------------------------your-apikey---------------------------";

domainList = deepviz_list_init(1);
if (domainList){
	
	deepviz_list_add(domainList, "<search_domain>");

	result = deepviz_advanced_search(api, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "M", NULL, NULL, deepviz_true, NULL, NULL, domainList, 0, 100);
	if (result){
		if (result->status == DEEPVIZ_STATUS_SUCCESS){
			printf("JSON RESULT: %s\n", result->msg);
		}
		else{
			printf("ERROR CODE: %d - MSG: %s\n", result->status, result->msg);
		}
	}
	
	deepviz_list_free(&domainList);
	deepviz_result_free(&result);
}
```
