"""Custom topology example
Two directly connected switches plus a host for each switch:
   host --- switch --- switch --- host
Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import RemoteController, OVSSwitch

class MyTopo( Topo ):
    "Simple topology example."

    def build( self ):
        "Create custom topo."

        # Add hosts and switches
        # h11 = self.addHost( 'h11', ip="10.0.0.1.100/24", defaultRoute="via 10.0.1.1" )
        # h12 = self.addHost( 'h12' , ip="10.0.0.1.101/24", defaultRoute="via 10.0.1.1" )

        # h21 = self.addHost( 'h21' , ip="10.0.0.2.100/24", defaultRoute="via 10.0.2.1" )
        # h22 = self.addHost( 'h22' , ip="10.0.0.2.101/24", defaultRoute="via 10.0.2.1" )

        h11 = self.addHost( 'h11', ip="10.0.1.100/24")
        h12 = self.addHost( 'h12' , ip="10.0.1.101/24")

        h21 = self.addHost( 'h21' , ip="10.0.2.100/24")
        h22 = self.addHost( 'h22' , ip="10.0.2.101/24")
        
        leftSwitch = self.addSwitch( 's1' )
        rightSwitch = self.addSwitch( 's2' )

        # Add links
        self.addLink( h11, leftSwitch )
        self.addLink( h12, leftSwitch )

        self.addLink( h21, rightSwitch )
        self.addLink( h22, rightSwitch )
        self.addLink( rightSwitch, leftSwitch )


#topos = { 'mytopo': ( lambda: MyTopo() ) }

topo = MyTopo()
topos = {
    'mytopo': MyTopo
}
net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        controller=RemoteController("C1", port=6633, ip="10.0.0.1/16"),
        autoSetMacs=True )

    # Actually start the network
net.start()

# Drop the user in to a CLI so user can run commands.
CLI( net )

# After the user exits the CLI, shutdown the network.
net.stop()