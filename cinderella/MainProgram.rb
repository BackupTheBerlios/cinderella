# $Id: MainProgram.rb,v 1.3 2003/06/24 12:32:59 ak1 Exp $

class MainProgram

  def initialize(argv)
    $logger.debug "MainProgram#initialize: argv[0] = #{argv[0]} argv[1] = #{argv[1]}"
    if argv[0] == "-r" and argv.size >= 2 then
      $logger.debug "MainProgram#initialize: opening pcap file"
      @cap = Pcap::Capture.open_offline(argv[1]);
    else
      $logger.debug "MainProgram#initialize: looking up device"
      @dev = Pcap.lookupdev
      $logger.debug "MainProgram#initialize: opening device"
      @cap = Pcap::Capture.open_live(@dev,65535,true,1000) # device, snaplen, promisc, timeout
    end
    $logger.debug "MainProgram#initialize: creating PacketDumper"
    @dumper = PacketDumper.new(@cap)
    $logger.debug "MainProgram#initialize: creating TcpProcessor"
    @tcp_proc = TcpProcessor.new(@cap,@dumper)
    $logger.debug "MainProgram#initialize: creating UdpProcessor"
    @udp_proc = UdpProcessor.new(@cap,@dumper)
    $logger.debug "MainProgram#initialize: creating IcmpProcessor"
    @icmp_proc = IcmpProcessor.new(@cap,@dumper)
    $logger.debug "MainProgram#initialize: creating OtherProcessor"
    @other_proc = OtherProcessor.new(@cap,@dumper)
  end

  def process_packet(pkt)
    $logger.debug "MainProgram#process_packet: entering process_packet"
    if (pkt.ip?) then
      $logger.debug "MainProgram#process_packet: got IP packet"
      if (pkt.tcp?) then
        $logger.debug "MainProgram#process_packet: got TCP packet"
        processor = @tcp_proc
      elsif (pkt.udp?) then
        $logger.debug "MainProgram#process_packet: got UDP packet"
        processor = @udp_proc
      elsif (pkt.icmp?) then
        $logger.debug "MainProgram#process_packet: got ICMP packet"
        processor = @icmp_proc
      else
        $logger.debug "MainProgram#process_packet: got some other packet"
        processor = @other_proc
      end
      $logger.debug "MainProgram#process_packet: calling processor.process_packet"
      processor.process_packet(pkt)
    end
  end


  def run
    $logger.debug "MainProgram#run: entering run"
    @cap.each_packet do |pkt|
      $logger.debug "MainProgram#run: processing packet"
      process_packet(pkt)
    end
  end

end # class MainProgram
