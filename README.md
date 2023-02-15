## Notice
1. This is the project of a gratuate school course, not the repo of the orginal [WECMP paper](https://ieeexplore.ieee.org/document/8549549).
2. The project was not implemented by myself only, and I am not sure whether it is the final integral version. (I cannot understand it now. lol)
3. I combined several [P4 exercises](https://github.com/p4lang/tutorials/tree/master/exercises) to write the code, mainly "load_balance" and "P4runtime".

## Environment
The download link of the developing environment is [here](https://mega.nz/file/h59iAKiL#XMwM-oqsVa1gnOfPIb73hs7knA_2xsHPLsee8CnEZ-0), but it is the "P4 Tutorial 2019-04-25" release. The latest version may be found on "[p4lang](https://github.com/p4lang/tutorials)".
After opening the VM, there is a "tutorials" folder which is very ancient version. Maybe you could clone the latest tutorials first, and then, clone this repo.
> "load_balance.p4.sw" and "topology.json.2" should be useless, I forget what they do.

## Testing
1. First, we neet to build it up.
	> $ cd /path/to/the/repo
	>
	> $ make run

	This command will start a Mininet instance, so we will see the command line become "mininet> ".
2. Open the node terminals. In this case, we have 2 nodes and 4 switchs.
	> mininet> xterm h1 h2
	
	Confirming whether the network is connected.
	> mininet> h1 ping h2
	
	Performing haevy communications between the nodes.
	> mininet> iperf h1 h2
3. Try the effect of load balance While iperf works.

	Node2 (h2)
	> $ ./receive.py
	
	Node1 (h1)
	> $ ./send.py 10.0.2.2 "test"
	
	The packet info would show in the node terminals.
