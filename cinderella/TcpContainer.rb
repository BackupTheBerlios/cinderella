# $Id: TcpContainer.rb,v 1.1 2003/06/03 11:13:26 ak1 Exp $

class TcpContainer

  TIMEOUT = 30

  def initialize
    @conn_list = Array.new
  end

  def stream_exists?(saddr,sport,daddr,dport)
    $logger.debug "TcpContainer#stream_exists?: I got #{@conn_list.size} streams"
    $logger.debug "TcpContainer#stream_exists?: Searching for stream..."
    @conn_list.each do |conn|
      return true if conn.match(saddr,sport,daddr,dport)
    end
    $logger.debug "TcpContainer#stream_exists?: No stream found"
    false
  end

  def get_stream(saddr,sport,daddr,dport)
    @conn_list.each do |conn|
      return conn if conn.match(saddr,sport,daddr,dport)
    end
    nil
  end

  def add_stream(saddr,sport,daddr,dport)
    new_conn = TcpConnection.new(saddr,sport,daddr,dport)
    @conn_list << new_conn
    new_conn
  end

  def remove_old_streams
    @conn_list.each_index do |i|
      if @conn_list[i].timeout?(TIMEOUT) then
        if not @conn_list[i].is_evaluated? then
          @conn_list[i].set_bad
          @conn_list[i].do_output_all
        end
        @conn_list[i] = nil
      end
    end
    @conn_list.compact!
  end

end
