# $Id: tcp_good.rb,v 1.1 2003/06/03 21:48:57 ak1 Exp $

class TcpModule

  def evaluate(conv) # parameter "conversation" not needed
    $logger.debug "TcpModule#evaluate: module good: evaluating stream to good"
    arr = Array.new
    arr << true
    arr << true
    return arr
  end

end
