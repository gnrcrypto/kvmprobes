rmmod kvm_probe_drv.ko
sleep 1
rm /bin/kvm_prober
sleep 1
bash build.sh
sleep 1
make
sleep 1
make install
