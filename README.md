# ROHC_P4
Robust header compression draft with P4

How to compile?
Place yourself in P4/bmv2
> sudo ./autogen.sh
> sudo make

How to test?
Place yourself in P4/tutorials/examples/rohc_decomp in two different terminals.
One of them execute:
> sudo ../veth_setup.sh
> sudo run_switch.sh

In the other one:
> sudo python send_and_receive.py
