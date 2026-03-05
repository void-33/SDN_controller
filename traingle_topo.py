from mininet.topo import Topo

class TriangleTopo( Topo ):
    "Simple Loop Topology (Triangle)"

    def build( self ):
        # Add switches
        s1 = self.addSwitch( 's1' )
        s2 = self.addSwitch( 's2' )
        s3 = self.addSwitch( 's3' )

        # Add hosts
        h1 = self.addHost( 'h1' )
        h2 = self.addHost( 'h2' )
        h3 = self.addHost( 'h3' )

        # Add links to hosts
        self.addLink( h1, s1 )
        self.addLink( h2, s2 )
        self.addLink( h3, s3 )

        # Add links between switches to form a loop
        self.addLink( s1, s2 )
        self.addLink( s2, s3 )
        self.addLink( s3, s1 )

topos = { 'triangle': ( lambda: TriangleTopo() ) }