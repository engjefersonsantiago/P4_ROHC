# ROHC_P4
Robust header compression draft with P4

How to setup the environment? Place yourself in P4/p4c-bmv2/
> sudo pip install -r requirements_v1_1.txt

Ignore (i) and continue.

How to compile?
Place yourself in P4/bmv2
If it is the first time run
> sudo ./autogen.sh
> sudo make clean
> sudo ./autogen.sh
> sudo make install
Else run,
> sudo ./autogen.sh
> sudo make 

How to test?
Place yourself in P4/tutorials/examples/rohc_decomp in two different terminals.
One of them execute:
> sudo ./../veth_setup.sh
> sudo ./run_switch.sh

In the other one:
> sudo python send_and_receive.py

##Ubuntu Image

The ubuntu image that we use for our testing can be found here - ubuntu-14.04.3-desktop-amd64.iso

 [ubuntu-14.04.3-desktop-amd64.iso]: <http://old-releases.ubuntu.com/releases/14.04.3/>
