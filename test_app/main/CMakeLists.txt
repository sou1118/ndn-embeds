idf_component_register(
    SRCS
        "test_main.cpp"
        "../../test/test_tlv.cpp"
        "../../test/test_name.cpp"
        "../../test/test_interest.cpp"
        "../../test/test_data.cpp"
        "../../test/test_signature.cpp"
        "../../test/test_link.cpp"
        "../../test/test_certificate.cpp"
        "../../test/test_pit.cpp"
        "../../test/test_cs.cpp"
        "../../test/test_fib.cpp"
        "../../test/test_forwarder.cpp"
        "../../test/test_espnow_face.cpp"
    INCLUDE_DIRS "."
    REQUIRES unity ndn
)
