
include $(RULESDIR)/common-windows.mk

CXX     := x86_64-w64-mingw32-g++
CC      := x86_64-w64-mingw32-gcc
AR      := x86_64-w64-mingw32-ar rcsD
DLLTOOL := x86_64-w64-mingw32-dlltool

LDFLAGS += -L/opt/windows/64/bin
LDFLAGS += -L/opt/windows/64/lib
CFLAGS  += -I/opt/windows/64/include

