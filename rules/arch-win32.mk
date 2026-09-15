
include $(RULESDIR)/common-windows.mk

CXX     := i686-w64-mingw32-g++ -m32
CC      := i686-w64-mingw32-gcc -m32
AR      := i686-w64-mingw32-ar rcsD
DLLTOOL := i686-w64-mingw32-dlltool

LDFLAGS += -L/opt/windows/32/bin
LDFLAGS += -L/opt/windows/32/lib
CFLAGS  += -I/opt/windows/32/include

