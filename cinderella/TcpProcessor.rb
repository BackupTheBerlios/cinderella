# $Id: TcpProcessor.rb,v 1.1 2003/06/03 11:13:26 ak1 Exp $

class TcpProcessor<PacketProcessor

  def initialize(capture,dumper)
    $logger.debug "TcpProcessor#initialize: creating TcpContainer object"
    @tcp_cont = TcpContainer.new
    $logger.debug "TcpProcessor#initialize: creating TcpModules object"
    @tcp_mod = TcpModules.new
    @capture = capture
    $logger.debug "TcpProcessor#initialize: opening dumper for good"
    @good_dumper = dumper.get_good_dumper
    $logger.debug "TcpProcessor#initialize: opening dumper for bad"
    @bad_dumper = dumper.get_bad_dumper
  end

  def process_packet(pkt)
    cur_stream = nil

    if not @tcp_cont.stream_exists?(pkt.ip_src,pkt.tcp_sport,pkt.ip_dst,pkt.tcp_dport) then
      $logger.debug "TcpProcessor#process_packet: stream #{pkt.ip_src}:#{pkt.tcp_sport} -> #{pkt.ip_dst}:#{pkt.tcp_dport} does not exist, adding stream"
      cur_stream = @tcp_cont.add_stream(pkt.ip_src,pkt.tcp_sport,pkt.ip_dst,pkt.tcp_dport)
      $logger.debug "TcpProcessor#process_packet: finding module for new stream"
      cur_stream.set_module(@tcp_mod.find_module(pkt))
      $logger.debug "TcpProcessor#process_packet: registering dumpers"
      cur_stream.register_dumpers(@good_dumper,@bad_dumper)
    else
      $logger.debug "TcpProcessor#process_packet: stream #{pkt.ip_src}:#{pkt.tcp_sport} -> #{pkt.ip_dst}:#{pkt.tcp_dport} exists"
      cur_stream = @tcp_cont.get_stream(pkt.ip_src,pkt.tcp_sport,pkt.ip_dst,pkt.tcp_dport)
    end

    if not cur_stream.is_evaluated? then
      $logger.debug "TcpProcessor#process_packet: stream is not yet evaluated. Adding packet"
      cur_stream.add_packet(pkt)
      $logger.debug "TcpProcessor#process_packet: trying to evaluate stream"
      cur_stream.try_evaluate

      if cur_stream.is_evaluated? then
        $logger.debug "TcpProcessor#process_packet: stream is evaluated now. Dumping all packets"
        cur_stream.do_output_all
      end
    else
      $logger.debug "TcpProcessor#process_packet: stream is evaluated. Dumping packet"
      cur_stream.do_output_packet(pkt)
    end

    $logger.debug "TcpProcessor#process_packet: removing old streams"
    @tcp_cont.remove_old_streams

  end

end
