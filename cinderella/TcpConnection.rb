# $Id: TcpConnection.rb,v 1.2 2003/08/02 17:39:05 ak1 Exp $

class TcpConnection

  STATE_CLOSED = 0
  STATE_SYN_SENT = 1
  STATE_LISTEN = 2
  STATE_SYN_RCVD = 3
  STATE_ESTABLISHED = 4
  STATE_CLOSE_WAIT = 5
  STATE_LAST_ACK = 6
  STATE_FIN_WAIT_1 = 7
  STATE_FIN_WAIT_2 = 8
  STATE_CLOSING = 9
  STATE_TIME_WAIT = 10

  def initialize(saddr,sport,daddr,dport)
    $logger.debug "TcpConnection#initialize: saddr = #{saddr} sport = #{sport} daddr = #{daddr} dport = #{dport}"
    @saddr = saddr
    @sport = sport
    @daddr = daddr
    @dport = dport
    @client_state = STATE_CLOSED
    @server_state = STATE_LISTEN
    @evaluated = false
    @good = false
    @module = nil
    @packet_list = Array.new
    @timestamp = Time.new
    $logger.debug "TcpConnection#initialize: timestamp = #{@timestamp}"
  end

  def set_bad
    $logger.debug "TcpConnection#set_bad: setting connection to bad"
    @evaluated = true
    @good = false
  end

  def register_dumpers(good,bad)
    $logger.debug "TcpConnection#register_dumpers: registering dumpers..."
    @good_dumper = good
    @bad_dumper = bad
    $logger.debug "TcpConnection#register_dumpers: finished"
  end

  def match(saddr,sport,daddr,dport)
    does_match = ((@saddr == saddr and @sport == sport and @daddr == daddr and @dport == dport) or (@saddr == daddr and @sport == dport and @daddr == saddr and @dport == sport))
    $logger.debug "TcpConnection#match: does_match = #{does_match}"
    does_match
  end

  def set_new_state(pkt)
    # this will be implemented according to Stevens UNP Vol. I, p. 38
    #
    # the client sends something
    if (pkt.ip_src == @saddr and pkt.tcp_sport == @sport) then
      $logger.debug "TcpConnection#set_new_state: client sends something"
      case @client_state
        when STATE_CLOSED then
          if (pkt.tcp_syn?) then
            $logger.debug "TcpConnection#set_new_state: setting state from STATE_CLOSED to STATE_SYN_SENT"
            @client_state = STATE_SYN_SENT
          else
            $logger.warn "TcpConnection#set_new_state: bogus STATE_CLOSED to STATE_SYN_SENT"
          end
        when STATE_SYN_SENT then
          if (not pkt.tcp_syn? and pkt.tcp_ack?) then
            $logger.debug "TcpConnection#set_new_state: setting state from STATE_SYN_SENT to STATE_ESTABLISHED"
            @client_state = STATE_ESTABLISHED
          else
            $logger.warn "TcpConnection#set_new_state: bogus STATE_SYN_SENT to STATE_ESTABLISHED"
          end
        when STATE_ESTABLISHED then
          if (pkt.tcp_fin?) then
            $logger.debug "TcpConnection#set_new_state: setting state from STATE_ESTABLISHED to STATE_FIN_WAIT_1"
            @client_state = STATE_FIN_WAIT_1
          end
        when STATE_FIN_WAIT_1 then
          if (pkt.tcp_ack?) then
            $logger.debug "TcpConnection#set_new_state: setting state from STATE_FIN_WAIT_1 to STATE_CLOSING"
            @client_state = STATE_CLOSING
          end
        when STATE_FIN_WAIT_2 then
          if (pkt.tcp_ack?) then
            $logger.debug "TcpConnection#set_new_state: setting state from STATE_FIN_WAIT_2 to STATE_TIME_WAIT"
            @client_state = STATE_TIME_WAIT
          else
            $logger.warn "TcpConnection#set_new_state: bogus STATE_FIN_WAIT_2 to STATE_TIME_WAIT"
          end
        else
          $logger.warn "TcpConnection#set_new_state: bogus state"
      end # case

      case @server_state
        when STATE_LISTEN then
          if (pkt.tcp_syn?) then
            $logger.debug "TcpConnection#set_new_state: setting state from STATE_LISTEN to STATE_SYN_RCVD"
            @server_state = STATE_SYN_RCVD
          else
            $logger.warn "TcpConnection#set_new_state: bogus STATE_LISTEN to STATE_SYN_RCVD"
          end
        when STATE_SYN_RCVD then
          if (pkt.tcp_ack?) then
            $logger.debug "TcpConnection#set_new_state: setting state from STATE_SYN_RCVD to STATE_ESTABLISHED"
            @server_state = STATE_ESTABLISHED
          else
            $logger.warn "TcpConnection#set_new_state: bogus STATE_SYN_RCVD to STATE_ESTABLISHED"
          end
        when STATE_ESTABLISHED then
          if (pkt.tcp_fin?) then
            $logger.debug "TcpConnection#set_new_state: setting state from STATE_ESTABLISHED to STATE_CLOSE_WAIT"
            @server_state = STATE_CLOSE_WAIT
          end
        when STATE_LAST_ACK then
          if (pkt.tcp_ack?) then
            $logger.debug "TcpConnection#set_new_state: setting state from STATE_LAST_ACK to STATE_CLOSED"
            @server_state = STATE_CLOSED # end of connection
            # connection shall be removed then
          else
            $logger.warn "TcpConnection#set_new_state: bogus STATE_LAST_ACK to STATE_CLOSED"
          end
      end

    # the server sends something
    elsif (pkt.ip_src == @daddr and pkt.tcp_sport == @dport) then
      # XXX I think this should be implemented, but cinderella works without it
    else
      $logger.warn "TcpConnection#set_new_state: completely bogus packet"
      # huh? packet must be bogus
    end
  end

  def add_packet(pkt)
    $logger.debug "TcpConnection#add_packet: adding packet to connection"
    @timestamp = Time.new
    self.set_new_state(pkt)
    @packet_list << pkt
  end

  def is_evaluated?
    $logger.debug "TcpConnection#is_evaluated? == #{@evaluated}"
    @evaluated
  end

  def get_conversation
    $logger.debug "TcpConnection#get_conversation: building conversation"

    conv = Array.new

    if @packet_list.size > 3 and @client_state >= STATE_ESTABLISHED then
      saddr = @packet_list[0].ip_src
      sport = @packet_list[0].tcp_sport
      data = ""
      @packet_list.each_index do |i|
        next if i < 3

        $logger.debug "TcpConnection#get_conversation: #{@packet_list[i]}"

        if @packet_list[i].tcp_ack? and @packet_list[i].tcp_psh? then

          new_saddr = @packet_list[i].ip_src
          new_sport = @packet_list[i].tcp_sport

          if (new_saddr == saddr) and (new_sport == sport) then
            $logger.debug "TcpConnection#get_conversation: #{new_saddr} = #{saddr} and #{new_sport} = #{sport}"
            data += @packet_list[i].tcp_data.dup
          else
            $logger.debug "TcpConnection#get_conversation: uhm, #{new_saddr} != #{saddr} or #{new_sport} != #{sport}"
            conv << data.dup
            data = @packet_list[i].tcp_data.dup
            saddr = new_saddr
            sport = new_sport
          end
          $logger.debug "TcpConnection#get_conversation: data = #{data}"
        end
      end

      conv << data

      #conv.shift # this is ugly

      $logger.debug "TcpConnection#get_conversation: done, size = #{conv.size}"

      conv
    end # if

#    $logger.debug "TcpConnection#get_conversation: dumping conv..."
#    conv.each do |x|
#      $logger.debug "TcpConnection#get_conversation: #{x.dump}"
#    end
#    $logger.debug "TcpConnection#get_conversation: end dump"

    return conv
  end

  def try_evaluate
    $logger.debug "TcpConnection#try_evaluate: I got #{@packet_list.size} packets"
    # 3 packets are the # of handshakes. we can't evaluate before we didn't have any conversation
    if @packet_list.size > 3 then
      $logger.debug "TcpConnection#try_evaluate: trying to evaluate connection"
      conv = get_conversation
      state = @module.evaluate(conv)
      $logger.debug "TcpConnection#try_evaluate: old evaluated = #{@evaluated} old good = #{@good}"
      @evaluated = state[0]
      @good = state[1]
      $logger.debug "TcpConnection#try_evaluate: new evaluated = #{@evaluated} new good = #{@good}"
    else
      $logger.debug "TcpConnection#try_evaluate: not yet evaluating stream..."
    end
  end

  def get_dumper
    if (not @evaluated or not @good) then
      $logger.debug "TcpConnection#get_dumper: returning bad dumper"
      @bad_dumper
    else
      $logger.debug "TcpConnection#get_dumper: returning good dumper"
      @good_dumper
    end
  end

  def do_output_all
    $logger.debug "TcpConnection#do_output_all: getting dumper"
    dumper = get_dumper
    $logger.debug "TcpConnection#do_output_all: dumping all packets"
    @packet_list.each do |pkt|
      dumper.dump(pkt)
    end
  end

  def do_output_packet(pkt)
    $logger.debug "TcpConnection#do_output_packet: dumping packet"
    get_dumper().dump(pkt)
  end

  def set_module(mod)
    $logger.debug "TcpConnection#set_module: setting new module"
    @module = mod
  end

  def timeout?(sec)
    timeout = (Time.new.to_i - @timestamp.to_i) >= sec
    $logger.debug "TcpConnection#timeout? is #{timeout}"
    timeout
  end

end
