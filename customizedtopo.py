from mininet.topo import Topo
from mininet.log import setLogLevel
from mininet.link import TCLink
from mininet.net import Mininet
from mininet.node import OVSController
from mininet.util import dumpNodeConnections
class MyTopo(Topo):
	def __init__(self):

		Topo.__init__(self)

		# Add hosts and switches
		host1 = self.addHost('h1')
		host2 = self.addHost('h2')
		host3 = self.addHost('h3')
		host4 = self.addHost('h4')
		switch1 =self.addSwitch('s1')
		switch2 =self.addSwitch('s2')
		switch3 =self.addSwitch('s3')
		switch4 =self.addSwitch('s4')
		
		# Add links
		self.addLink(switch1,switch2,2,1)
		self.addLink(switch1,switch4,3,1)
		self.addLink(switch2,switch3,3,1)
		self.addLink(switch4,switch3,2,3)
		
		self.addLink(switch1,host1,1,1)
		self.addLink(switch2,host2,2,1)
		self.addLink(switch3,host3,2,1)
		self.addLink(switch4,host4,3,1)
def controller():
	topo = MyTopo()
	net = Mininet( topo=topo, controller=lambda name: RemoteController(name, ip='127.0.0.1'), switc=OVSSwitch, autoSetMacs=True )
	net.start()
	CLI(net)
	net.stop()
	
if __name__=='__main__':
	setLogLevel('info')
	controller()

topos = { 'mytopo': (lambda:MyTopo())}
