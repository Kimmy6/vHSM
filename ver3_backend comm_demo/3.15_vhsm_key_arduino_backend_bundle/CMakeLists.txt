cmake_minimum_required(VERSION 3.16)
project(VirtualHSM LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

if (MSVC)
    add_compile_options(/Zc:__cplusplus)
endif()

find_package(Qt6 REQUIRED COMPONENTS Core Gui Qml Quick QuickControls2 Concurrent)

qt_add_executable(VirtualHSM
    main.cpp
    resources.qrc
    src/controllers/AppController.cpp
    src/models/AppState.cpp
    src/services/AuthService.cpp
    src/services/CryptoService.cpp
    src/services/PiGatewayService.cpp
    src/services/MldsaService.cpp
    src/utils/FileUtils.cpp
)

target_include_directories(VirtualHSM PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/controllers
    ${CMAKE_CURRENT_SOURCE_DIR}/src/models
    ${CMAKE_CURRENT_SOURCE_DIR}/src/services
    ${CMAKE_CURRENT_SOURCE_DIR}/src/utils
)

if(ANDROID)
    target_include_directories(VirtualHSM PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/botan/android_arm64/include/botan-3
    )

    target_link_libraries(VirtualHSM PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/botan/android_arm64/lib/libbotan-3.a
    )
endif()

target_link_libraries(VirtualHSM PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Qml
    Qt6::Quick
    Qt6::QuickControls2
    Qt6::Concurrent
)

qt_finalize_executable(VirtualHSM)