#define NOB_IMPLEMENTATION

#include "nob.h"

// locally built openssl-3.5
#define OSSL_DIR "./openssl"

int
main(int argc, char** argv)
{
  NOB_GO_REBUILD_URSELF(argc, argv);
  Nob_Cmd cmd = {0};
  nob_cmd_append(&cmd, 
      "cc", 
      "-Wall", 
      "-Wextra", 
      "-Wpedantic", 
      "-std=c11",
      "-I"OSSL_DIR"/include",
      "-g",
      "-o", 
      "bin/server", 
      "src/server.c",
      OSSL_DIR"/libssl.a",
      OSSL_DIR"/libcrypto.a"
      );
  if (!nob_cmd_run_sync(cmd)) return 1;
  return 0;
}
