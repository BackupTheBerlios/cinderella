# $Id: tcp_http.rb,v 1.1 2003/06/03 21:48:57 ak1 Exp $

class TcpModule

  def initialize
    goodlist_file = "etc/http_goodlist.txt" # the file with allowed requests
    $logger.debug "HTTPModule#initialize: initializing HTTP module..."
    @regexps = Array.new
    IO.foreach(goodlist_file) do |line|
      line.chomp!
      $logger.debug "HTTPModule#initialize: adding #{line.dump} to @regexps..."
      @regexps << line
    end
    $logger.debug "HTTPModule#initialize: done reading #{goodlist_file}"
  end

  def evaluate(conv)
    retval = Array.new
    if conv.size > 0 then
      $logger.debug "HTTPModule#evaluate: checking #{conv[0].dump}..."
      retval << true # first element means "evaluated"
      @regexps.each do |re|
        $logger.debug "HTTPModule#evaluate: #{conv[0].dump} =~ #{re} ?"
        if conv[0] =~ re then
          $logger.debug "HTTPModule#evaluate: yes"
          retval << true # second element means "good"
          return retval
        else
          $logger.debug "HTTPModule#evaluate: no"
        end
      end
    else
      retval << false
      retval << true
    end
    return retval
  end

end
