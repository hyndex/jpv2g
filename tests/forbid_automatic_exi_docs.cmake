if(NOT DEFINED SECC_SOURCE)
    message(FATAL_ERROR "SECC_SOURCE is required")
endif()

file(READ "${SECC_SOURCE}" SECC_TEXT)

# Generated EXI documents are tens of kilobytes. A declaration whose token
# after the document type is an identifier (rather than '*') is an automatic
# object unless separately qualified; no such object belongs in secc.c. Keep
# this source-level guard because an ordinary host test has ample stack and
# would not reproduce the ESP32-S3 worker-creation failure.
string(REGEX MATCH
       "struct[ \t\r\n]+(appHand|iso2|din)_exiDocument[ \t\r\n]+[A-Za-z_][A-Za-z0-9_]*[ \t\r\n]*(\\[|;|=)"
       AUTOMATIC_EXI_DECLARATION
       "${SECC_TEXT}")

if(AUTOMATIC_EXI_DECLARATION)
    message(FATAL_ERROR
            "Automatic EXI document detected in secc.c: ${AUTOMATIC_EXI_DECLARATION}")
endif()
