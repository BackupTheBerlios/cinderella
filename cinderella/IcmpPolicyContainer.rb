# $Id: IcmpPolicyContainer.rb,v 1.2 2003/06/24 12:32:59 ak1 Exp $

class IcmpPolicyContainer

  def initialize
    $logger.debug "IcmpPolicyContainer#initialize: reading configuration..."
    @modules = ConfigReader.new("cind.conf").get_icmp_policies
    $logger.debug "IcmpPolicyContainer#initialize: done reading configuration"
  end

  def have_policy(pkt)
    @modules.each do |m|
      return true if m.match_policy(pkt)
    end
    return false
  end

end
