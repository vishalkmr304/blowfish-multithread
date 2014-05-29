project(blowfish-multithread)

add_executable(blowfish-multithread main.c)

install(TARGETS blowfish-multithread RUNTIME DESTINATION bin)
