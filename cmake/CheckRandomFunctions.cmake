include(CheckCSourceCompiles)

# Skip checks for Emscripten
if(EMSCRIPTEN)
    message(STATUS "Skipping random function checks for Emscripten")
    return()
endif()

# Check for getrandom with standard API
set(_GETRANDOM_CODE "
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_SYS_RANDOM_H
# include <sys/random.h>
#endif

int main() {
    unsigned char buf;
    if (&getrandom != NULL) {
        (void) getrandom((void *) &buf, 1U, 0U);
    }
    return 0;
}
")

message(STATUS "Checking for getrandom with standard API")
check_c_source_compiles("${_GETRANDOM_CODE}" HAVE_GETRANDOM_STANDARD)

if(HAVE_GETRANDOM_STANDARD)
    message(STATUS "getrandom with standard API: yes")
    set(HAVE_GETRANDOM TRUE)
else()
    message(STATUS "getrandom with standard API: no")
    set(HAVE_GETRANDOM FALSE)
endif()

# Check for getentropy with standard API
set(_GETENTROPY_CODE "
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_SYS_RANDOM_H
# include <sys/random.h>
#endif

int main() {
    unsigned char buf;
    if (&getentropy != NULL) {
        (void) getentropy((void *) &buf, 1U);
    }
    return 0;
}
")

message(STATUS "Checking for getentropy with standard API")
check_c_source_compiles("${_GETENTROPY_CODE}" HAVE_GETENTROPY_STANDARD)

if(HAVE_GETENTROPY_STANDARD)
    message(STATUS "getentropy with standard API: yes")
    set(HAVE_GETENTROPY TRUE)
else()
    message(STATUS "getentropy with standard API: no")
    set(HAVE_GETENTROPY FALSE)
endif() 