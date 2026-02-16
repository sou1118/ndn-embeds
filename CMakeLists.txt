idf_component_register(
    SRCS
        "src/common.cpp"
        "src/tlv.cpp"
        "src/name.cpp"
        "src/interest.cpp"
        "src/data.cpp"
        "src/link.cpp"
        "src/certificate.cpp"
        "src/crypto.cpp"
        "src/pit.cpp"
        "src/cs.cpp"
        "src/fib.cpp"
        "src/face.cpp"
        "src/forwarder.cpp"
        "src/api.cpp"
        "adapters/espnow_face.cpp"
    INCLUDE_DIRS
        "include"
        "adapters"
    REQUIRES
        esp_timer
        esp_wifi
        mbedtls
)

target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_23)
