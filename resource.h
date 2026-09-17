#pragma once

// Version - bump here; the .rc VERSIONINFO (and code, if desired) read these.
#define CPG_VER_MAJOR 1
#define CPG_VER_MINOR 0
#define CPG_VER_PATCH 0
#define CPG_VER_BUILD 0

#define CPG_VER_NUM  CPG_VER_MAJOR, CPG_VER_MINOR, CPG_VER_PATCH, CPG_VER_BUILD
#define CPG__STR2(x) #x
#define CPG__STR(x)  CPG__STR2(x)
#define CPG_VER_STR  CPG__STR(CPG_VER_MAJOR) "." CPG__STR(CPG_VER_MINOR) "." \
                      CPG__STR(CPG_VER_PATCH) "." CPG__STR(CPG_VER_BUILD)
