#!/usr/bin/ruby

# (c) 2002-2003 Andreas Krennmair <ak@synflood.at>
# prototype for the NIDS codename "cinderella"
# $Id: cind.rb,v 1.1 2003/06/03 11:13:24 ak1 Exp $

require 'pcap'
require 'log4r'

require("TcpConfigEntry")
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
require("UdpContainer")
require("UdpProcessor")

Log4r::Logger.root.level = Log4r::WARN
$logger = Log4r::Logger.new("cinderella")
Log4r::StderrOutputter.new('console')
#Log4r::FileOutputter.new('cind.log',{'filename' => 'cind.log'})
$logger.add('console')

mainprog = MainProgram.new(ARGV)

Kernel.exit(mainprog.run)
