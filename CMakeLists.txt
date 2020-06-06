cmake_minimum_required(VERSION 3.15)
project(untitled1)

set(CMAKE_CXX_STANDARD 14)


if(APPLE)
    include_directories(/usr/local/openssl-1.1/include/)
    include_directories(/usr/local/opt/openssl@1.1/include/openssl/)
    include_directories(/usr/local/opt/openssl@1.1/include/)
    include_directories(/usr/local/openssl-1.1/include/openssl/)
    #include_directories(/usr/local/include/)
    include_directories(/usr/local/Cellar/leveldb/1.22/include/)
    link_directories(/usr/local/Cellar/leveldb/1.22/lib/)
    #link_directories(/usr/local/src/openssl-1.1.0f/)
    link_directories(/usr/local/opt/openssl@1.1/lib)
    link_libraries(crypto.1.1)

    link_directories(/usr/local/opt/pcsc-lite/lib/)
    include_directories(/usr/local/opt/pcsc-lite/include/PCSC/)
    link_libraries(pcsclite)

elseif(UNIX)
    include_directories(/usr/include/openssl/)
    link_libraries(crypto)
endif()

include_directories(/usr/include/openssl/)
link_libraries(ssl)

add_executable(untitled1
        main.cpp

        NtpRsk/NtpRsk.cpp
        NtpRsk/NtpRsk.h
        NtpRsk/NtpRskSignatureRequestObject.h
        NtpRsk/NtpRskSignatureVerificationObject.h
        Tools/Hexdump.cpp
        Tools/Hexdump.h
        Crypto/Sha256.cpp
        Crypto/Sha256.h
        Crypto/ECCtools.cpp
        Crypto/ECCtools.h
        )