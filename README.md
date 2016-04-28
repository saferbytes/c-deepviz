# c-deepviz

c-deepviz is a C library wrapper for deepviz.com REST APIs

## Supported platforms
- Windows
- Linux

## Usage 

To use Deepviz API SDK you will need an API key. You can get it by
subscribing the service for free at https://account.deepviz.com/register/

You can download the latest release of the precompiled binaries from https://github.com/saferbytes/c-deepviz/releases or you can also recompile from sources as well. Make sure you always download the latest release's sources.

The complete Deepviz REST APIs documentation can be found at https://api.deepviz.com/docs/

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

RedHat / Fedora / CentOS:

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

deepviz_result_free(result);
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

deepviz_result_free(result);
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

deepviz_result_free(result);
```

To retrieve full scan report for a specific MD5:

```C++
#include "c-deepviz.h"

...
PDEEPVIZ_RESULT result = NULL;
const char* md5 = "-----------file-md5-------------";
const char* apikey = "--------------------------your-apikey---------------------------";

result = deepviz_sample_report(md5, apikey);
if (result){
    if (result->status == DEEPVIZ_STATUS_SUCCESS){
        printf("JSON RESULT: %s\n", result->msg);
    }
    else{
        printf("ERROR CODE: %d - MSG: %s\n", result->status, result->msg);
    }
}

deepviz_result_free(result);
```

To send a bulk download request and download the related archive containing the requested files:

```C++
#include "c-deepviz.h"

...
PDEEPVIZ_RESULT         result1 = NULL;
PDEEPVIZ_RESULT         result2 = NULL;
PDEEPVIZ_LIST           md5List = NULL;
DEEPVIZ_RESULT_STATUS   currentStatus;
const char*             apikey = "--------------------------your-apikey---------------------------";

md5List = deepviz_list_init(<number_of_md5>);
if (md5List){

    deepviz_list_add(md5List, "-----------MD5-1----------------");
    ...
    deepviz_list_add(md5List, "-----------MD5-n----------------");
  
    result1 = deepviz_bulk_download_request(md5List, apikey);
    if (result1){
        if (result1->status == DEEPVIZ_STATUS_SUCCESS){
		/* "msg" contains request ID on success */
        
            printf("BULK REQUEST ID: %s\n", result1->msg);
            do{
            /* Loop while the archive is not ready to download */
                
                result2 = deepviz_bulk_download_retrieve(result->msg, ""<download_folder_path>"", apikey);
                if (result2){
                    printf("STATUS: %d - MSG: %s\n", result2->status, result2->msg);
                }

                currentStatus = result2->status;

                deepviz_result_free(&result2);

                Sleep(1000);

            } while (currentStatus == DEEPVIZ_STATUS_PROCESSING);
        }
        else{
           printf("ERROR CODE: %d - MSG: %s\n", result1->status, result1->msg);
        }
   }
   
   deepviz_list_free(&md5List);
   deepviz_result_free(&result1);
}
```

#### Threat Intelligence

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

deepviz_result_free(result);
```

To retrieve only specific parts of the report of a specific MD5 scan:

```C++
#include "c-deepviz.h"

...
PDEEPVIZ_RESULT result = NULL;
PDEEPVIZ_LIST    filters = NULL;
const char* md5 = "-----------file-md5-------------";
const char* apikey = "--------------------------your-apikey---------------------------";

filters = deepviz_list_init(<number_of_filters>);
if (filters){

    deepviz_list_add(filters, "<deepviz_filter_1>");
    ...
    deepviz_list_add(filters, "<deepviz_filter_n>");

    result = deepviz_sample_info(md5, apikey, filters);
    if (result){
        if (result->status == DEEPVIZ_STATUS_SUCCESS){
            printf("JSON RESULT: %s\n", result->msg);
        }
        else{
            printf("ERROR CODE: %d - MSG: %s\n", result->status, result->msg);
        }
    }

    deepviz_list_free(filters);
    deepviz_result_free(result);
}
```

To retrieve intel data about one or more IPs:

```C++
#include "c-deepviz.h"

...
PDEEPVIZ_RESULT result = NULL;
PDEEPVIZ_LIST    ipList = NULL;
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

    deepviz_list_free(ipList);
    deepviz_result_free(result);
}
```

To retrieve intel data about one or more domains:

```C++
#include "c-deepviz.h"

...
PDEEPVIZ_RESULT result = NULL;
PDEEPVIZ_LIST    domainList = NULL;
PDEEPVIZ_LIST    filters = NULL;
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

    deepviz_list_free(domainList);
    deepviz_list_free(filters);
    deepviz_result_free(result);
}
```

To retrieve newly registered domains in the last 7 days:

```C++
#include "c-deepviz.h"

...
PDEEPVIZ_RESULT result = NULL;
PDEEPVIZ_LIST    filters = NULL;
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

    deepviz_list_free(filters);
    deepviz_result_free(result);
}
```

To run generic search based on strings 
(find all IPs, domains, samples related to the searched keyword):

```C++
#include "c-deepviz.h"

...
PDEEPVIZ_RESULT result = NULL;
PDEEPVIZ_LIST    filters = NULL;
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

deepviz_result_free(result);
```

To run advanced search based on parameters
(find the first 100 samples md5 connecting to a domain and determined as malicious):

```C++
#include "c-deepviz.h"

...
PDEEPVIZ_RESULT result = NULL;
PDEEPVIZ_LIST    domainList = NULL;
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
    
    deepviz_list_free(domainList);
    deepviz_result_free(result);
}
```
