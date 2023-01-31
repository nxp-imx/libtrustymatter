cmake_minimum_required(VERSION 3.22)

project(storageproxyd)

aux_source_directory(storage STORAGE_LOCAL)
aux_source_directory(libtrusty LIBTRUSTY_LOCAL)
include_directories("./storage")
include_directories("./storage/include")
include_directories("./storage/include/linux")
include_directories("./libtrusty/include")
add_executable(storageproxyd ${STORAGE_LOCAL} ${LIBTRUSTY_LOCAL})

install(TARGETS storageproxyd  DESTINATION sbin)

find_package(PkgConfig)
include(GNUInstallDirs)
pkg_check_modules(SYSTEMD systemd)

if(SYSTEMD_FOUND)
    pkg_get_variable(SYSTEMD_UNIT_DIR systemd systemdsystemunitdir)
endif()

install(FILES storage//storageproxyd.service DESTINATION ${SYSTEMD_UNIT_DIR})
