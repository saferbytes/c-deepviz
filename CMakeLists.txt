cmake_minimum_required(VERSION 2.8)
project(c-deepviz)

file(GLOB_RECURSE SOURCE_FILES src/*.c)

if (WIN32)
    set(CompilerFlags CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE )
    foreach(CompilerFlag ${CompilerFlags})
        string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
    endforeach()

endif()

if (WIN32)
    # Force to always compile with W4
    if(CMAKE_C_FLAGS MATCHES "/W[0-4]")
        string(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4996")
    else()
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4")
    endif()
elseif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
    # Update if necessary
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wno-long-long -Wno-unused-function")
endif()

add_library(c-deepviz SHARED ${SOURCE_FILES})
#add_executable(c-deepviz ${SOURCE_FILES} src/sandbox.c src/intel.c src/c-deepviz_private.h)

if (NOT WIN32 AND (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX))
    target_link_libraries(c-deepviz ${CMAKE_CURRENT_SOURCE_DIR}/external-libs/jansson-2.7/linux/libjansson.a)

    # NOTE: MUST INSTALL LIBCURL-DEV -> apt-get install libcurl4-openssl-dev
    FIND_PACKAGE(CURL)
    IF(CURL_FOUND)
        INCLUDE_DIRECTORIES(${CURL_INCLUDE_DIR})
        SET(requiredlibs ${requiredlibs} ${CURL_LIBRARIES} )
        target_link_libraries(c-deepviz ${CURL_LIBRARIES})
    ELSE(CURL_FOUND)
        MESSAGE(FATAL_ERROR "Could not find the CURL library and development files.")
    ENDIF(CURL_FOUND)

endif()

