cmake_minimum_required(VERSION 3.13)
project(pqTLS_master)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 11)

find_package(OpenSSL)


SET(NISTFLAGS "-march=native" "-mtune=native" "-O0" "-fomit-frame-pointer")
SET(NISTFLAGS "${NISTFLAGS}" "-DMODE=1" "-DUSE_AES")



set(SOURCES "newhope/kem.c" "newhope/cpapke.c" "dilithium1aes/rng.c" "newhope/fips202nh.c"
        "newhope/nttnh.c" "newhope/polynh.c" "newhope/precomp.c" "newhope/reducenh.c"
        "newhope/rngnh.c" "newhope/verify.c" "dilithium1aes/sign.c"
        "dilithium1aes/polyvec.c" "dilithium1aes/poly.c" "dilithium1aes/packing.c"
        "dilithium1aes/ntt.c" "dilithium1aes/reduce.c" "dilithium1aes/rounding.c"
        "dilithium1aes/fips202.c" "dilithium1aes/aes256ctr.c" "opensslaes.c")


add_executable(client "client_tls_pq.c" "pq.c" "${SOURCES}")
target_compile_options(client BEFORE PRIVATE "${NISTFLAGS}")
target_link_libraries(client "${OPENSSL_LIBRARIES}")


add_executable(server "server_tls_pq.c" "pq.c" "${SOURCES}")
target_compile_options(server BEFORE PRIVATE "${NISTFLAGS}")
target_link_libraries(server "${OPENSSL_LIBRARIES}")


## CLASSICS
add_executable(client_npq "client_tls_pq.c" "npq.c" "ecdh/ecdh.c" "${SOURCES}")
target_compile_options(client_npq  BEFORE PRIVATE "${NISTFLAGS}")
target_link_libraries(client_npq "${OPENSSL_LIBRARIES}")

add_executable(server_npq "server_tls_pq.c" "npq.c" "ecdh/ecdh.c" "${SOURCES}")
target_compile_options(server_npq BEFORE PRIVATE "${NISTFLAGS}")
target_link_libraries(server_npq "${OPENSSL_LIBRARIES}")



file(COPY bash.sh DESTINATION "${pqTLS_master_BINARY_DIR}")
file(COPY bash2.sh DESTINATION "${pqTLS_master_BINARY_DIR}")
file(COPY server.sh DESTINATION "${pqTLS_master_BINARY_DIR}")
