# $Id: OtherProcessor.rb,v 1.1 2003/06/03 11:13:24 ak1 Exp $

#require("PacketProcessor")

class OtherProcessor<PacketProcessor

  def initialize(cap, dumper)
    @cap = cap
    @dumper = dumper
  end

  def process_packet(pkt)
    $logger.debug "OtherProcessor#process_packet: dumping some other packet"
    @dumper.get_bad_dumper.dump(pkt)
  end

end
