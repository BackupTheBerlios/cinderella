# $Id: UdpProcessor.rb,v 1.2 2003/06/03 21:41:05 ak1 Exp $

class UdpProcessor<PacketProcessor

  def initialize(cap,dumper)
    @udp_mod = UdpModules.new
    @cap = cap
    @dumper = dumper
  end

  def process_packet(pkt)
    if @udp_mod.find_module(pkt).evaluate(pkt) then # packet is good
      $logger.debug "UdpProcessor#process_packet: dumping good UDP packet"
      @dumper.get_good_dumper.dump(pkt)
    else
      $logger.debug "UdpProcessor#process_packet: dumping bad UDP packet"
      @dumper.get_bad_dumper.dump(pkt)
    end
  end

end
