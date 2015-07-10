# Install pcre-8.37
if [ ! -f /usr/local/lib/libpcre.a ]; then
	tar xvfz pcre-8.37.tar.gz
	cd pcre-8.37/
	./configure
	make
	sudo make install
	cd ../
	sudo rm -rf pcre-8.37/
fi
# Install swig-3.0.5
if [ ! -d /usr/local/share/swig/ ]; then
	tar xvfz swig-3.0.5.tar.gz
	cd swig-3.0.5/
	./configure
	make
	sudo make install
	cd ..
	sudo rm -rf swig-3.0.5/
fi

# Refresh ldconfig
sudo ldconfig

# Install libntoh
if [ ! -f /usr/local/lib/libntoh.a ]; then
	cd libntoh/
	mkdir -p install
	cd src/
	mkdir -p build
	cd build/
	cmake .. 
	make
	sudo make install
	cd ..
	sudo rm -rf build/
	cd ../../
fi
# Back to vendors/
sudo ldconfig
