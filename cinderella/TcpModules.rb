# $Id: TcpModules.rb,v 1.1 2003/06/03 11:13:26 ak1 Exp $

# a little helper class for TcpModules
class TcpModules


  def initialize
    $logger.debug "TcpModules#initialize: reading configuration..."
    @modules = ConfigReader.new("cind.conf").get_tcp_modules
    $logger.debug "TcpModules#initialize: done reading configuration"
  end

  def find_module(pkt)
    @modules.each do |mod|
      src_str = pkt.ip_src.to_s + ":" + pkt.sport.to_s
      dst_str = pkt.ip_dst.to_s + ":" + pkt.dport.to_s
      $logger.debug "TcpModules#find_module: trying to match #{src_str} and #{dst_str}"
      if (mod.match(src_str,dst_str)) then
        $logger.debug "TcpModules#find_module: strings match"
        return mod.get_module
      end
    end
    $logger.debug "TcpModules#find_module: strings do not match"
    return BadModule.new
  end

end
