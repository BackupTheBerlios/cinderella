# $Id: TcpConnection.rb,v 1.4 2003/08/02 22:27:26 ak1 Exp $

class TcpConnection

# possible TCP states
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

  DIR_NONE   = 0
  DIR_SERVER = 1
  DIR_CLIENT = 2

# taken from <netinet/tcp.h>
  TH_FIN  = 0x01
  TH_SYN  = 0x02
  TH_RST  = 0x04
  TH_PUSH = 0x08
  TH_ACK  = 0x10
  TH_URG  = 0x20
  TH_ECE  = 0x40
  TH_CWR  = 0x80

  def initialize(saddr,sport,daddr,dport)
    $logger.debug "TcpConnection#initialize: saddr = #{saddr} sport = #{sport} daddr = #{daddr} dport = #{dport}"
    @saddr = saddr
    @sport = sport
    @daddr = daddr
    @dport = dport
    @client_state = STATE_CLOSED
    @server_state = STATE_LISTEN
    @fin_sent = DIR_NONE
    @evaluated = false
    @good = false
    @module = nil
    @packet_list = Array.new
    @timestamp = Time.new
    $logger.debug "TcpConnection#initialize: timestamp = #{@timestamp}"
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
    # this algorithm is taken from snort

    if (pkt.ip_src == @saddr and pkt.tcp_sport == @sport) then
      direction = DIR_CLIENT
    elsif (pkt.ip_dst == @saddr and pkt.tcp_dport == @sport) then
      direction = DIR_SERVER
    else
      $logger.warn "TcpConnection#set_new_state: totally bogus packet"
    end

    if pkt.tcp_fin? then
      @fin_sent = direction
    end

    case direction

      when DIR_SERVER then

        case @client_state
          when STATE_SYN_SENT then
            if pkt.tcp_flags == (TH_SYN|TH_ACK) then
              @client_state = STATE_ESTABLISHED
              $logger.debug "TcpConnection#set_new_state: client transition: ESTABLISHED"
              return
            elsif  pkt.tcp_flags == (TH_RST) then
              @client_state = STATE_CLOSED
              @server_state = STATE_CLOSED
              $logger.debug "TcpConnection#set_new_state: client transition: CLOSED"
              $logger.debug "TcpConnection#set_new_state: server transition: CLOSED"
            end

          when STATE_ESTABLISHED then
            if pkt.tcp_flags == (TH_FIN|TH_ACK) then
              @client_state = STATE_CLOSE_WAIT
              @server_state = STATE_FIN_WAIT_1
              $logger.debug "TcpConnection#set_new_state: client transition: CLOSE_WAIT"
              $logger.debug "TcpConnection#set_new_state: server transition: FIN_WAIT_1"
            elsif pkt.tcp_flags == (TH_FIN|TH_ACK|TH_PUSH) then

              $logger.debug "TcpConnection#set_new_state: got FIN PSH ACK"
              @client_state = STATE_CLOSE_WAIT
              @server_state = STATE_FIN_WAIT_1
              $logger.debug "TcpConnection#set_new_state: client transition: CLOSE_WAIT"
              $logger.debug "TcpConnection#set_new_state: server transition: FIN_WAIT_1"
            elsif pkt.tcp_flags == TH_FIN then
              @client_state = STATE_CLOSE_WAIT
              @server_state = STATE_FIN_WAIT_1
              $logger.debug "TcpConnection#set_new_state: client transition: CLOSE_WAIT"
              $logger.debug "TcpConnection#set_new_state: server transition: FIN_WAIT_1"
            elsif pkt.tcp_rst? then
              @client_state = STATE_CLOSED
              @server_state = STATE_CLOSED
              $logger.debug "TcpConnection#set_new_state: client transition: CLOSED"
              $logger.debug "TcpConnection#set_new_state: server transition: CLOSED"
            elsif pkt.tcp_ack? then
              $logger.debug "TcpConnection#set_new_state: ACKing client data"
            end

            return

          when STATE_FIN_WAIT_1 then
            if pkt.tcp_rst? then
              @server_state = STATE_CLOSED
              @client_state = STATE_CLOSED
              $logger.debug "TcpConnection#set_new_state: client transition: CLOSED"
              $logger.debug "TcpConnection#set_new_state: server transition: CLOSED"
            elsif pkt.tcp_flags == (TH_FIN|TH_ACK) then
              @server_state = STATE_LAST_ACK
              @client_state = STATE_FIN_WAIT_2
              $logger.debug "TcpConnection#set_new_state: client transition: FIN_WAIT_2"
              $logger.debug "TcpConnection#set_new_state: server transition: LAST_ACK"
            elsif pkt.tcp_ack? then
              @server_state = STATE_CLOSE_WAIT
              @client_state = STATE_FIN_WAIT_2
              $logger.debug "TcpConnection#set_new_state: client transition: FIN_WAIT_2"
              $logger.debug "TcpConnection#set_new_state: server transition: CLOSE_WAIT"
            end

            return

          when STATE_FIN_WAIT_2 then
            if pkt.tcp_flags == (TH_FIN|TH_ACK) then
              @client_state = STATE_TIME_WAIT
              @server_state = STATE_LAST_ACK
              $logger.debug "TcpConnection#set_new_state: client transition: TIME_WAIT"
              $logger.debug "TcpConnection#set_new_state: server transition: LAST_ACK"
            elsif pkt.tcp_flags == TH_FIN then
              @client_state = STATE_TIME_WAIT
              @server_state = STATE_LAST_ACK
              $logger.debug "TcpConnection#set_new_state: client transition: TIME_WAIT"
              $logger.debug "TcpConnection#set_new_state: server transition: LAST_ACK"
            end

            return

          when STATE_LAST_ACK then
            if pkt.tcp_ack? then
              @client_state = STATE_CLOSED
              $logger.debug "TcpConnection#set_new_state: client transition: CLOSED"
            end
            return

          when STATE_CLOSE_WAIT then
            if pkt.tcp_flags == TH_RST then
              @server_state = STATE_CLOSED
              @client_state = STATE_CLOSED
              $logger.debug "TcpConnection#set_new_state: client transition: CLOSED"
              $logger.debug "TcpConnection#set_new_state: server transition: CLOSED"
            elsif pkt.tcp_flags == (TH_ACK|TH_PUSH|TH_FIN) then
              @server_state = STATE_FIN_WAIT_2
              @client_state = STATE_LAST_ACK
              $logger.debug "TcpConnection#set_new_state: client transition: LAST_ACK"
              $logger.debug "TcpConnection#set_new_state: server transition: FIN_WAIT_2"
            elsif pkt.tcp_ack? then
              @server_state = STATE_FIN_WAIT_2
              $logger.debug "TcpConnection#set_new_state: server transition: FIN_WAIT_2"
            end
            return

        end # case @client_state

      when DIR_CLIENT then

        case @server_state 

          when STATE_LISTEN then
            $logger.debug "TcpConnection#set_new_state: server state: LISTEN"
            if pkt.tcp_syn? and not pkt.tcp_rst? then

              @server_state = STATE_SYN_RCVD
              @client_state = STATE_SYN_SENT
              $logger.debug "TcpConnection#set_new_state: client transition: SYN_SENT"
              $logger.debug "TcpConnection#set_new_state: server transition: SYN_RCVD"
            end
            return

          when STATE_SYN_RCVD then
            if pkt.tcp_rst? then
              @server_state = STATE_CLOSED
              @client_state = STATE_CLOSED
              $logger.debug "TcpConnection#set_new_state: client transition: CLOSED"
              $logger.debug "TcpConnection#set_new_state: server transition: CLOSED"
            elsif pkt.tcp_ack? then
              @server_state = STATE_ESTABLISHED
              $logger.debug "TcpConnection#set_new_state: server transition: ESTABLISHED"
            end
            return

          when STATE_ESTABLISHED then
            if pkt.tcp_flags == (TH_FIN|TH_ACK) then
              @client_state = STATE_FIN_WAIT_1
              @server_state = STATE_CLOSE_WAIT
              $logger.debug "TcpConnection#set_new_state: client transition: FIN_WAIT_1"
              $logger.debug "TcpConnection#set_new_state: server transition: CLOSE_WAIT"
            elsif pkt.tcp_flags == (TH_FIN|TH_ACK|TH_PUSH) then
              @client_state = STATE_CLOSE_WAIT
              @server_state = STATE_FIN_WAIT_1
              $logger.debug "TcpConnection#set_new_state: client transition: CLOSE_WAIT"
              $logger.debug "TcpConnection#set_new_state: server transition: FIN_WAIT_1"
            elsif pkt.tcp_rst? then
              @server_state = CLOSED
              @client_state = CLOSED
              $logger.debug "TcpConnection#set_new_state: client transition: CLOSED"
              $logger.debug "TcpConnection#set_new_state: server transition: CLOSED"
            end

            return

          when STATE_LAST_ACK then
            if pkt.tcp_ack? then
              @server_state = CLOSED
              $logger.debug "TcpConnection#set_new_state: server transition: CLOSED"
            end
            return

          when STATE_FIN_WAIT_1 then
            if pkt.tcp_flags == (TH_ACK|TH_FIN) then
              @client_state = STATE_LAST_ACK
              @server_state = STATE_FIN_WAIT_2
              $logger.debug "TcpConnection#set_new_state: client transition: LAST_ACK"
              $logger.debug "TcpConnection#set_new_state: server transition: FIN_WAIT_2"
            elsif pkt.tcp_rst? then
              @server_state = STATE_CLOSED
              @client_state = STATE_CLOSED
              $logger.debug "TcpConnection#set_new_state: client transition: CLOSED"
              $logger.debug "TcpConnection#set_new_state: server transition: CLOSED"
            elsif pkt.tcp_flags == TH_ACK then
              @server_state = STATE_FIN_WAIT_2
              @client_state = STATE_CLOSE_WAIT
              $logger.debug "TcpConnection#set_new_state: client transition: CLOSE_WAIT"
              $logger.debug "TcpConnection#set_new_state: server transition: FIN_WAIT_2"
            end
            return

          when STATE_FIN_WAIT_2 then
            if pkt.tcp_flags == (TH_FIN|TH_ACK) then
              @server_state = STATE_TIME_WAIT
              @client_state = STATE_LAST_ACK
              $logger.debug "TcpConnection#set_new_state: client transition: LAST_ACK"
              $logger.debug "TcpConnection#set_new_state: server transition: TIME_WAIT"
            elsif pkt.tcp_flags == TH_FIN then
              @server_state = STATE_TIME_WAIT
              @client_state = STATE_LAST_ACK
              $logger.debug "TcpConnection#set_new_state: client transition: LAST_ACK"
              $logger.debug "TcpConnection#set_new_state: server transition: TIME_WAIT"
            end
            return

          when STATE_CLOSE_WAIT then
            if pkt.tcp_flags == TH_RST then
              @server_state = STATE_CLOSED
              @client_state = STATE_CLOSED
              $logger.debug "TcpConnection#set_new_state: client transition: CLOSED"
              $logger.debug "TcpConnection#set_new_state: server transition: CLOSED"
            elsif pkt.tcp_ack? then
              @client_state = STATE_FIN_WAIT_2
              $logger.debug "TcpConnection#set_new_state: client transition: FIN_WAIT_2"
            end
            return

        end # case @server_state

    end # case direction

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
          $logger.debug "TcpConnection#get_conversation: data = #{data.dump}"
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
    if self.client_closed? and self.server_closed? then
      true # when the connection is closed, we have "timeout"
      # (actually a trick to remove closed connections together with the
      # timed out connections)
    else
      timeout = (Time.new.to_i - @timestamp.to_i) >= sec
      $logger.debug "TcpConnection#timeout? is #{timeout}"
      timeout
    end
  end

  def set_bad
    $logger.debug "TcpConnection#set_bad: setting connection to bad"
    @evaluated = true
    @good = false
  end

  def client_closed?
    @client_state == STATE_CLOSED
  end

  def server_closed?
    @server_state == STATE_CLOSED
  end

end
