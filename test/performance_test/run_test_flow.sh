# prepare test folder
test_folder=csv_tests/$(date +%s)_test
user=user
mkdir $test_folder
chown $user $test_folder

# pwd starts in the performance test folder
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

#-------------------------------------------------------------------- zone sync --------------------------------------------------------------------

make
insmod hook.ko

python3 user/agent_zone.py &
AGENT_PID=$!

popd
python3 jit_test_fine.py $test_folder/zone_sync.csv
chown $user $test_folder/zone_sync.csv
pushd ../..

kill -TERM $AGENT_PID
wait $AGENT_PID
rmmod hook

# #---------------------------------------------------------------------- page sync --------------------------------------------------------------------

make PAGE=y
insmod hook.ko

python3 user/agent_page.py &
AGENT_PID=$!

popd
python3 jit_test_fine.py $test_folder/zone_sync.csv
chown $user $test_folder/zone_sync.csv
pushd ../..

kill -TERM $AGENT_PID
wait $AGENT_PID
rmmod hook













