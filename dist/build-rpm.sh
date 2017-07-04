version="1.6.9.2"
release=$(git log --format="%h" -n 1)
platform=$(uname -s)
arch=$(uname -p)
# Where the sdk/ compiled source code
sdk_dir=../sdk

# Set name of package with given version
rpm_name="mmt-dpi_${version}_${release}_${platform}_${arch}"
build_dir=$rpm_name

# Create a directory with the name of package
mkdir -p $build_dir

echo "-]> Preparing temporary location ..."
mkdir -p $build_dir/opt/mmt/dpi/lib
mkdir -p $build_dir/opt/mmt/dpi/include
mkdir -p $build_dir/opt/mmt/examples
mkdir -p $build_dir/opt/mmt/plugins
mkdir -p $build_dir/etc/ld.so.conf.d/

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
echo "/opt/mmt/dpi/lib" >> $build_dir/etc/ld.so.conf.d/mmt-dpi.conf


echo "-]> Building .rpm file ..."

mkdir -p ./rpmbuild/{RPMS,BUILD}
echo -e\
    "Summary:  MMT-DPI\
    \nName: mmt-dpi\
    \nVersion: ${version}\
    \nRelease: ${release}\
    \nLicense: proprietary\
    \nGroup: Development/Libraries\
    \nURL: http://montimage.com/\
    \n\
    \nBuildRoot: %{_topdir}/BUILD/%{name}-%{version}-%{release}\
    \n\
    \n%description\
    \nMMT-DPI is a library for deep packet inspection.\
    \nBuild date: `date +"%Y-%m-%d %H:%M:%S"`\
    \n\
    \n%prep\
    \nrm -rf %{buildroot}\
    \nmkdir -p %{buildroot}/\
    \ncp -r %{_topdir}/../${build_dir}/* %{buildroot}/\
    \nmkdir -p %{buildroot}/etc/ld.so.conf.d/\
    \n\
    \n%clean\
    \nrm -rf %{buildroot}\
    \n\
    \n%files\
    \n%defattr(-,root,root,-)\
    \n/opt/mmt/*\
    \n/etc/ld.so.conf.d/mmt-dpi.conf\
    \n%post\
    \nldconfig\
" > ./mmt-dpi.spec

rpmbuild --quiet --rmspec --define "_topdir $(pwd)/rpmbuild" --define "_rpmfilename ../../$rpm_name.rpm" -bb ./mmt-dpi.spec

echo "-]> Removing temporary location ..."
rm -rf $build_dir rpmbuild

echo "-]> $rpm_name.rpm has been created!"
echo "-]> Run command to install: "
echo "sudo yum -i $rpm_name.rpm"
