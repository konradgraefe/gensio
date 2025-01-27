/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIOTCL_DLLVISIBILITY
#define GENSIOTCL_DLLVISIBILITY

#if defined _WIN32 || defined __CYGWIN__
  #ifdef BUILDING_GENSIOTCL_DLL
    #ifdef __GNUC__
      #define GENSIOTCL_DLL_PUBLIC __attribute__ ((dllexport))
    #else
      #define GENSIOTCL_DLL_PUBLIC __declspec(dllexport) // Note: actually gcc seems to also supports this syntax.
    #endif
  #else
    #ifdef __GNUC__
      #define GENSIOTCL_DLL_PUBLIC __attribute__ ((dllimport))
    #else
      #define GENSIOTCL_DLL_PUBLIC __declspec(dllimport) // Note: actually gcc seems to also supports this syntax.
    #endif
  #endif
  #define GENSIOTCL_DLL_LOCAL
#else
  #if __GNUC__ >= 4
    #define GENSIOTCL_DLL_PUBLIC __attribute__ ((visibility ("default")))
    #define GENSIOTCL_DLL_LOCAL  __attribute__ ((visibility ("hidden")))
  #else
    #define GENSIOTCL_DLL_PUBLIC
    #define GENSIOTCL_DLL_LOCAL
  #endif
#endif

#endif /* GENSIOTCL_DLLVISIBILITY */
