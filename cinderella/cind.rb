#!/usr/bin/ruby

# (c) 2002-2003 Andreas Krennmair <ak@synflood.at>
# prototype for the NIDS codename "cinderella"
# $Id: cind.rb,v 1.4 2003/06/05 18:05:37 ak1 Exp $

require 'pcap'
require 'log4r'

require("ConfigEntry")
require("TcpConfigEntry")
require("UdpConfigEntry")
require("ConfigReader")
require("PacketDumper")
require("MainProgram")
require("OtherContainer")
require("PacketProcessor")
require("OtherProcessor")
require("TcpConnection")
require("TcpContainer")
require("BadModule")
require("TcpModules")
require("TcpProcessor")
require("IcmpPolicy")
require("IcmpPolicyContainer")
require("IcmpProcessor")
require("UdpModules")
require("UdpProcessor")

Log4r::Logger.root.level = Log4r::WARN
$logger = Log4r::Logger.new("cinderella")
Log4r::StderrOutputter.new('console')
#Log4r::FileOutputter.new('cind.log',{'filename' => 'cind.log'})
$logger.add('console')

mainprog = MainProgram.new(ARGV)

Kernel.exit(mainprog.run)
