# $Id: UdpProcessor.rb,v 1.1 2003/06/03 11:13:26 ak1 Exp $

class UdpProcessor<PacketProcessor

  def initialize(cap,dumper)
    @udp_cont = UdpContainer.new
    #@udp_mod = UdpModules.new
    @cap = cap
    @dumper = dumper
  end

  def process_packet(pkt)
    $logger.debug "UdpProcessor#process_packet: dumping UDP packet"
    @dumper.get_bad_dumper.dump(pkt)
  end

end
