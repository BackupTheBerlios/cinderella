# $Id: BadModule.rb,v 1.2 2003/06/03 21:41:05 ak1 Exp $

class TcpBadModule
  def evaluate(conv) # conversation not needed
    $logger.debug "TcpBadModule#evaluate: entering evaluate function"
    arr = Array.new
    arr << true
    arr << false
    $logger.debug "TcpBadModule#evaluate: leaving evaluate function"
    return arr
  end
end


class UdpBadModule
  def evaluate(pkt)
    $logger.debug "UdpModule#evaluate: entering and leaving evaluate function"
    false # packet is not good
  end
end
