# $Id: IcmpProcessor.rb,v 1.1 2003/06/05 18:05:37 ak1 Exp $

class IcmpProcessor<PacketProcessor

  def initialize(cap, dumper)
    @icmp_pol = IcmpPolicyContainer.new
    @cap = cap
    @dumper = dumper
  end

  def process_packet(pkt)
    if @icmp_pol.have_policy(pkt) then # packet is allowed according to policy
      $logger.debug "IcmpProcessor#process_packet: dumping good ICMP packet"
      @dumper.get_good_dumper.dump(pkt)
    else
      $logger.debug "IcmpProcessor#process_packet: dumping bad ICMP packet"
      @dumper.get_bad_dumper.dump(pkt)
    end
  end

end
