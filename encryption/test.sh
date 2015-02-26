rm -rf debug.lock
rm -rf *.log
touch shared.log

node server &> node0.log &	# Sends Signed to 1
node server &> node1.log &	# Receives Signed messages
node server &> node2.log &	# Forges Signed messages pretending to be from 0

tail -f shared.log
