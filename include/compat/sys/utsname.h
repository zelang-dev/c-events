/* sys/utsname.h

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#ifndef _SYS_UTSNAME_H
#define _SYS_UTSNAME_H

#ifdef __cplusplus
extern "C" {
#endif

#define _UTSNAME_LENGTH 65

/* Structure describing the system and machine.  */
struct utsname {
  /* Name of the implementation of the operating system.  */
  char sysname[_UTSNAME_LENGTH + 1];
  /* Name of this node on the network.  */
  char nodename[_UTSNAME_LENGTH];
  /* Current release level of this implementation.  */
  char release[_UTSNAME_LENGTH];
  /* Current version level of this release.  */
  char version[_UTSNAME_LENGTH];
  /* Name of the hardware type the system is running on.  */
  char machine[_UTSNAME_LENGTH];
#if __GNU_VISIBLE
  char domainname[_UTSNAME_LENGTH];
#else
  char __domainname[_UTSNAME_LENGTH];
#endif
};

/* Put information about the system in NAME.  */
int uname(struct utsname *);

#ifdef __cplusplus
}
#endif

#endif
