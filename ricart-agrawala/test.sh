rm -rf debug.lock
rm -rf *.log
touch shared.log

node server &> node1.log &
node server &> node2.log &
node server &> node3.log &
node server &> node4.log &

tail -f shared.log


