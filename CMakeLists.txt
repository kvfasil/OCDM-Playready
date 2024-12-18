# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
# Copyright 2020 Metrological
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.3)
project(DRMPlayready)

if (DEFINED MAKE_VERBOSE)
    set(CMAKE_VERBOSE_MAKEFILE TRUE)
endif()

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

set(DRM_PLUGIN_NAME "Playready")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -w -Wno-psabi ")

if(NOT CMAKE_CROSSCOMPILING)
   set(STAGING_DIR "${CMAKE_INSTALL_PREFIX}")
else()
   set(STAGING_DIR "${CMAKE_FIND_ROOT_PATH}")
endif()

file(GLOB DRM_PLUGIN_INCLUDES *.h)

set(DRM_PLUGIN_LIBS 
    ${PLAYREADY_LIBRARIES})

set(DRM_PLUGIN_SOURCES 
    MediaSession.cpp 
    MediaSystem.cpp
    MediaSessionExt.cpp)

# add the library
add_library(${DRM_PLUGIN_NAME} SHARED ${DRM_PLUGIN_SOURCES})
target_compile_definitions(${DRM_PLUGIN_NAME} PRIVATE ${PLAYREADY_FLAGS})

set_target_properties(${DRM_PLUGIN_NAME} PROPERTIES SUFFIX ".drm")
set_target_properties(${DRM_PLUGIN_NAME} PROPERTIES PREFIX "")

find_package(PlayReady REQUIRED)
if(PLAYREADY_FOUND)
    message(STATUS "PlayReady found!")
    # message(STATUS "${PLAYREADY_INCLUDE_DIRS}")
    include_directories(${PLAYREADY_INCLUDE_DIRS})
    include_directories(${PLAYREADY_LIBRARIES})
    target_link_libraries(${DRM_PLUGIN_NAME} playready-4.4)
else()
    message(FATAL_ERROR "PlayReady not found. Please install the required libraries.")
endif()

find_package(OpenSSL REQUIRED)
target_link_libraries(${DRM_PLUGIN_NAME} OpenSSL::SSL)

# Enable SVP.
#if("${RDK_SVP}" STREQUAL "ENABLED")
    message(STATUS "Using RDK_SVP")
    add_definitions (-DUSE_SVP)
    target_include_directories(${DRM_PLUGIN_NAME} PRIVATE ${CMAKE_SYSROOT}/usr/include/gstreamer-1.0)
    target_include_directories(${DRM_PLUGIN_NAME} PRIVATE ${CMAKE_SYSROOT}/usr/include/glib-2.0)
    target_include_directories(${DRM_PLUGIN_NAME} PRIVATE ${CMAKE_SYSROOT}/usr/lib/glib-2.0/include)
    #target_link_libraries(${DRM_PLUGIN_NAME} gstsvpext)
    target_link_libraries(${DRM_PLUGIN_NAME} gstamlsvpext)
#endif()

if("${DYNAMIC_SVP_DECRYPTION}" STREQUAL "ON")
    add_definitions( -DDYNAMIC_SVP_DECRYPTION )
    message(STATUS "DYNAMIC_SVP_DECRYPTION is ON")
else()
    message(STATUS "DYNAMIC_SVP_DECRYPTION is OFF")
endif()

if("${RESOLUTION_CHECK_ENABLED}" STREQUAL "ON")
    add_definitions( -DRESOLUTION_CHECK_ENABLED )
    message(STATUS "RESOLUTION_CHECK_ENABLED is ON")
else()
    message(STATUS "DYNAMIC_SVP_DECRYPTION is OFF")
endif()

if("${NO_PERSISTENT_LICENSE_CHECK}" STREQUAL "ON")
    add_definitions( -DNO_PERSISTENT_LICENSE_CHECK=1 )
    message(STATUS "NO_PERSISTENT_LICENSE_CHECK is ON")
else()
    message(STATUS "NO_PERSISTENT_LICENSE_CHECK is OFF")
endif()

install(TARGETS ${DRM_PLUGIN_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/share/WPEFramework/OCDM)

if(NOT "${CMAKE_FIND_ROOT_PATH}" STREQUAL "")
    install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink /etc/playready  ${CMAKE_CURRENT_BINARY_DIR}/playready)")
    install(DIRECTORY DESTINATION ${CMAKE_INSTALL_PREFIX}/../${PERSISTENT_PATH}/OCDM)
    install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/playready DESTINATION ${CMAKE_INSTALL_PREFIX}/../${PERSISTENT_PATH}/OCDM/)
endif()

