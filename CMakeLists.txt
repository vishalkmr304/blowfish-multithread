project(blowfish-multithread)

add_executable(blowfish-multithread blowfish.c main.c)

find_package (Threads)
target_link_libraries (blowfish-multithread ${CMAKE_THREAD_LIBS_INIT})
install(TARGETS blowfish-multithread RUNTIME DESTINATION bin)
