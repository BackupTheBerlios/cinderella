# $Id: PacketDumper.rb,v 1.1 2003/06/03 11:13:24 ak1 Exp $

class PacketDumper

  def initialize(capture)
    $logger.debug "PacketDumper#initialize: opening dumper for good"
    @good_dumper = Pcap::Dumper.open(capture,"good")
    $logger.debug "PacketDumper#initialize: opening dumper for bad"
    @bad_dumper = Pcap::Dumper.open(capture,"bad")
    @capture = capture
  end

  def get_bad_dumper
    @bad_dumper
  end

  def get_good_dumper
    @good_dumper
  end
end
