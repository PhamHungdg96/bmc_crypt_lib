include(CheckCSourceCompiles)
include(CheckFunctionExists)

# Check for alloca function
check_function_exists(alloca HAVE_ALLOCA)

if(HAVE_ALLOCA)
    message(STATUS "alloca function is available")
else()
    message(STATUS "alloca function is NOT available")
endif() 