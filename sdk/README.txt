
BUILDING ON LINUX FOR LINUX (native build):

  make -j4

  (-j4 instructs make to parallelize the build)


BUILDING ON LINUX FOR WINDOWS (cross-compilation):

Cross-compiling for windows requires mingw-w64 (NOT mingw32, as this version is deprecated)
and some Windows libraries (libxml, etc...).

All the required Windows libraries can be found in /windows on the public share.
Make expects the files to be available locally in /opt/windows/.

Here's what my setup looks like:

oprs@oxps% ls -l /opt/windows/
total 12
drwxr-xr-x 7 oprs oprs 4096 May 28 16:38 32
drwxr-xr-x 7 oprs oprs 4096 May 28 16:17 64

So assuming the public share directory was mounted on /mnt/share, just do:

  sudo mkdir -p /opt
  sudo cp -R /mnt/share/windows /opt/

(you can discard the 'packages' directory, it just contains the original archives)

Then build either a 32-bit version of the SDK:

  make -j4 ARCH=win32

... or a 64-bit version:

  make -j4 ARCH=win64

BUILDING ON OSX FOR OSX

1. Install tools:

* XCode
* Install Hombrew

    ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
    
2. Install library

    brew install gcc48
    #brew install cmake libpth-dev ldconfig 
    brew install libxml2 hiredis confuse libpcap
    
3. Compile SDK and install it

    make -j4 ARCH=osx
    sudo make ARCH=osx install