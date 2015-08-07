# Where the sdk/ compiled source code
sdk_dir=../sdk

# Set name of package with given version
build_dir=mmt_sdk

# Create a directory with the name of package
mkdir $build_dir

# Copy make file
cp ZIP/* $build_dir

# Copy source to zip file
cp -R $sdk_dir/include $build_dir
cp -R $sdk_dir/lib $build_dir
cp -R $sdk_dir/examples $build_dir

# Zip file
zip -r mmt_sdk.zip $build_dir

# Remove temp folder

rm -rf $build_dir
