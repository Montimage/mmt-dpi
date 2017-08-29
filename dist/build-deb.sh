version=1.6.10.5
# Where the sdk/ compiled source code
sdk_dir=../sdk

# Set name of package with given version
build_dir=mmt-dpi_1.6.10.5_`uname -s`_`uname -p`_`date +%s`

# Create a directory with the name of package
mkdir $build_dir

# Create control
mkdir $build_dir/DEBIAN/
cp DEBIAN/* $build_dir/DEBIAN/

echo "-]> Preparing temporary location ..."
mkdir $build_dir/opt/
mkdir $build_dir/opt/mmt/
mkdir $build_dir/opt/mmt/dpi
mkdir $build_dir/opt/mmt/dpi/lib
mkdir $build_dir/opt/mmt/dpi/include
mkdir $build_dir/opt/mmt/examples
mkdir $build_dir/opt/mmt/plugins
mkdir $build_dir/etc
mkdir $build_dir/etc/ld.so.conf.d/

echo "-]> Copying resource ..."
cp -R $sdk_dir/lib $build_dir/opt/mmt/dpi
cd $build_dir/opt/mmt/dpi/lib/
ln -s libmmt_core.so.* libmmt_core.so
ln -s libmmt_fuzz.so.* libmmt_fuzz.so
ln -s libmmt_security.so.* libmmt_security.so
ln -s libmmt_tcpip.so.* libmmt_tcpip.so
cd ../../../../../
cp -R $sdk_dir/include $build_dir/opt/mmt/dpi
cp -R $sdk_dir/examples $build_dir/opt/mmt
cp $sdk_dir/lib/libmmt_tcpip.so.$version $build_dir/opt/mmt/plugins/libmmt_tcpip.so
echo "/opt/mmt/dpi/lib" >> $build_dir/etc/ld.so.conf.d/mmt.conf


echo "-]> Building .deb file ..."
dpkg-deb --build $build_dir

echo "-]> Removing temporary location ..."
rm -rf $build_dir

echo "-]> $build_dir.deb has been created!"
echo "-]> Run command to install: "
echo "sudo dpkg -i $build_dir.deb"
