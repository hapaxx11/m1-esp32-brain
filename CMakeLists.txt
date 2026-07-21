cmake_minimum_required(VERSION 3.16)

set(EXTRA_COMPONENT_DIRS
    "${CMAKE_CURRENT_LIST_DIR}/components"
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Release version, exposed via esp_app_desc.version and reported to qMonstatek
# in device info (shown as "m1_link <ver>").
set(PROJECT_VER "1.0.0")

project(m1-esp32-brain)
