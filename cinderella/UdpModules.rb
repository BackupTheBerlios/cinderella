# $Id: UdpModules.rb,v 1.2 2003/06/04 17:17:17 ak1 Exp $

class UdpModules

  def initialize
    $logger.debug "UdpModules#initialize: reading configuration..."
    @modules = ConfigReader.new("cind.conf").get_udp_modules
    $logger.debug "UdpModules#initialize: done reading configuration"
  end

  def find_module(pkt)
    @modules.each do |mod|
      src_str = pkt.ip_src.to_s + ":" + pkt.sport.to_s
      dst_str = pkt.ip_dst.to_s + ":" + pkt.dport.to_s
      $logger.debug "UdpModules#find_module: trying to match #{src_str} and #{dst_str}"
      if (mod.match(src_str,dst_str)) then
        $logger.debug "UdpModules#find_module: strings match"
        return mod.get_module
      end
    end
    $logger.debug "TcpModules#find_module: strings do not match"
    return UdpBadModule.new
  end

end
