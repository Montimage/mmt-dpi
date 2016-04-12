# Where the sdk/ compiled source code
sdk_dir=../sdk

# Set name of package with given version
build_dir=mmt_sdk1.6.1.0`uname -s`_`uname -p`_`date +%Y-%m-%d`

# Create a directory with the name of package
mkdir $build_dir

# Create control
mkdir $build_dir/DEBIAN/
cp DEBIAN/* $build_dir/DEBIAN/

mkdir $build_dir/usr/
mkdir $build_dir/usr/local/
mkdir $build_dir/usr/local/include/
mkdir $build_dir/usr/local/include/mmt/
cp -R $sdk_dir/include/* $build_dir/usr/local/include/mmt/
echo "#include \"mmt/mmt_core.h\"">>$build_dir/usr/local/include/mmt_core.h
cp -R $sdk_dir/lib $build_dir/usr/

mkdir $build_dir/opt/
mkdir $build_dir/opt/mmt/
mkdir $build_dir/opt/mmt/plugins
cp $sdk_dir/lib/libmmt_tcpip.so $build_dir/opt/mmt/plugins
cp -R $sdk_dir/examples/ $build_dir/opt/mmt

dpkg-deb --build $build_dir

rm -rf $build_dir

echo "To install mmt-sdk library"
echo "sudo dpkg -i $build_dir.deb"
