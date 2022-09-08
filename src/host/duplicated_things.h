#ifndef HOST_DUPLICATED_THINGS_H
#define HOST_DUPLICATED_THINGS_H
//- This header deals with conflict includes between enclaves and hosts
//- When running inside enclaves, codes with the same defs are fine
//- When running outside enclaves, this will result in "duplicated definitions"
//- To tackle this, we need to include things separately for the above two modes

#if RUN_OUTSIDE_SGX
//- logging
#include "sgxbutil/logging.h"

#else 
//- logging
#include "utils/easylogging++.h"

#endif //- RUN_OUTSIDE_SGX
#endif //- HOST_DUPLICATED_THINGS_H