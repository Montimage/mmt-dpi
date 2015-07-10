# Install python-dev
sudo apt-get install -y python-dev

# Install pcre-8.37
tar xvfz pcre-8.37.tar.gz
cd pcre-8.37/
./configure
make
sudo make install
sudo rm -rf pcre-8.37/
cd ../

# Install swig-3.0.5
tar xvfz swig-3.0.5.tar.gz
cd swig-3.0.5/
./configure
make
sudo make install
sudo rm -rf swig-3.0.5/
cd ..

# Refresh ldconfig
sudo ldconfig

# Install libntoh
cd libntoh/
mkdir -p install
cd src/
mkdir -p build
cd build/
cmake .. -DCMAKE_INSTALL_PREFIX=../../install
make
sudo make install

# Back to vendors/
cd ../../../
sudo ldconfig
