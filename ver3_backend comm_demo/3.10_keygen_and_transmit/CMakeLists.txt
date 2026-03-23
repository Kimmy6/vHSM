cmake_minimum_required(VERSION 3.16)
project(VirtualHSM LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)

if (MSVC)
    add_compile_options(/Zc:__cplusplus)
endif()

find_package(Qt6 REQUIRED COMPONENTS Core Gui Qml Quick QuickControls2 Concurrent)

qt_add_executable(VirtualHSM
    main.cpp
    src/controllers/AppController.cpp
    src/models/AppState.cpp
    src/services/AuthService.cpp
    src/services/CryptoService.cpp
    src/services/PiGatewayService.cpp
    src/utils/FileUtils.cpp
)

qt_add_resources(VirtualHSM "app_resources"
    PREFIX "/"
    FILES
        qml/Main.qml

        qml/components/AppButton.qml
        qml/components/AppHeader.qml
        qml/components/AppTextField.qml
        qml/components/LoadingSpinner.qml

        qml/pages/ConnectPage.qml
        qml/pages/ConnectLoadingPage.qml
        qml/pages/UploadPage.qml
        qml/pages/ActionPage.qml
        qml/pages/WorkLoadingPage.qml
        qml/pages/RegenerateKeyPage.qml

        qml/styles/Theme.qml
        qml/styles/qmldir

        assets/fonts/NotoSansKR-Regular.ttf
)

target_include_directories(VirtualHSM PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/controllers
    ${CMAKE_CURRENT_SOURCE_DIR}/src/models
    ${CMAKE_CURRENT_SOURCE_DIR}/src/services
    ${CMAKE_CURRENT_SOURCE_DIR}/src/utils
)

target_link_libraries(VirtualHSM PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Qml
    Qt6::Quick
    Qt6::QuickControls2
    Qt6::Concurrent
)