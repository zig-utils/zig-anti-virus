/* Links the static library through the public header. */
#include "zav.h"

int main(void) {
  if (zav_abi_version() != 1) return 1;
  (void)zav_version_v1();
  return 0;
}
