# $Id: ConfigReader.rb,v 1.1 2003/06/03 11:13:24 ak1 Exp $

class ConfigReader

  def initialize(cf)
    @config_file = cf
  end

  def get_tcp_modules
    modules = Array.new
    begin
      $logger.debug "ConfigReader#get_tcp_modules: opening cind.conf"
      conf_file = File.new(@config_file)
    rescue
      $logger.error "ConfigReader#get_tcp_modules: unable to open cind.conf"
      puts "Unable to open cind.conf\n"
      Kernel.exit(1)
    end
    conf_file.each_line do |line|
      line.chomp!
      fields = line.split(/ /)
      if fields[0] == "tcp" then
        $logger.debug "ConfigReader#get_tcp_modules: adding new entry #{fields[0]} #{fields[1]} #{fields[2]} #{fields[3]}"
        modules << TcpConfigEntry.new(fields[1],fields[2], fields[3])
      end
    end
    $logger.debug "ConfigReader#get_tcp_modules: closing cind.conf"
    conf_file.close
    modules
  end

end
