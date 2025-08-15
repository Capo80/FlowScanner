# prepare test folder
test_folder=csv_tests/$(date +%s)_test
user=user
mkdir $test_folder
chown $user $test_folder

# pwd starts in the jit-bench folder
pushd ../..


# prepare test languages
# apt-get update
# apt install php-cli -y
# apt install luajit -y
# apt install lua-posix -y
# apt install ruby -y
#
# # # no env :)
# pip3 install numpy
# pip3 install pandas

#-------------------------------------------------------------------- pin --------------------------------------------------------------------

popd
python3 jit_test_fine.py $test_folder/pin.csv pin
chown $user $test_folder/pin.csv
pushd ../..


#-------------------------------------------------------------------- dynamorio --------------------------------------------------------------------

popd
python3 jit_test_fine.py $test_folder/dynamo.csv dynamo
chown $user $test_folder/dynamo.csv
pushd ../..


#-------------------------------------------------------------------- not mod --------------------------------------------------------------------

popd
python3 jit_test_fine.py $test_folder/no_module.csv
chown $user $test_folder/no_module.csv
pushd ../..

#-------------------------------------------------------------------- qemu --------------------------------------------------------------------

popd
python3 jit_test_fine.py $test_folder/qemu.csv qemu
chown $user $test_folder/qemu.csv
pushd ../..










