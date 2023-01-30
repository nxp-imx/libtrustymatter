cmake_minimum_required(VERSION 3.22)

project(storageproxyd)

aux_source_directory(storage STORAGE_LOCAL)
aux_source_directory(libtrusty LIBTRUSTY_LOCAL)
include_directories("./storage")
include_directories("./storage/include")
include_directories("./storage/include/linux")
include_directories("./libtrusty/include")
add_executable(storageproxyd ${STORAGE_LOCAL} ${LIBTRUSTY_LOCAL})
