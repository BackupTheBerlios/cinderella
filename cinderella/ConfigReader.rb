# $Id: ConfigReader.rb,v 1.3 2003/06/04 17:17:17 ak1 Exp $

class ConfigReader

  def initialize(cf)
    @config_file = cf
    get_modules
  end

  def get_modules
    if @modules then # get_modules has already been called
      return @modules
    else
      @modules = Array.new
      begin
        $logger.debug "ConfigReader#get_modules: opening cind.conf"
        conf_file = File.new(@config_file)
      rescue
        $logger.error "ConfigReader#get_modules: unable to open cind.conf"
        puts "Unable to open cind.conf\n"
        Kernel.exit(1)
      end
      conf_file.each_line do |line|
        line.chomp!
        fields = line.split(/ /)
        @modules << fields unless line ~= /^#/
      end
      $logger.debug "ConfigReader#get_modules: closing cind.conf"
      conf_file.close
      @modules
    end
  end

  def get_tcp_modules
    tcp_modules = Array.new
    @modules.each do |x|
      tcp_modules << TcpConfigEntry.new(x[1],x[2],x[3]) if (x[0] == "tcp")
    end
    $logger.debug "ConfigReader#get_tcp_modules: returning TCP modules"
    tcp_modules
  end

  def get_udp_modules
    udp_modules = Array.new
    @modules.each do |x|
      udp_modules << UdpConfigEntry.new(x[1],x[2],x[3]) if (x[0] == "udp")
    end
    $logger.debug "ConfigReader#get_tcp_modules: returning UDP modules"
    udp_modules
  end

end
