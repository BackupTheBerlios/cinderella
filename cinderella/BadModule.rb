# $Id: BadModule.rb,v 1.1 2003/06/03 11:13:24 ak1 Exp $

class BadModule
  def evaluate(conv) # conversation not needed
    $logger.debug "BadModule#evaluate: entering evaluate function"
    arr = Array.new
    arr << true
    arr << false
    $logger.debug "BadModule#evaluate: leaving evaluate function"
    return arr
  end
end
