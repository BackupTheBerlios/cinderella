# $Id: UdpConfigEntry.rb,v 1.2 2003/06/04 17:17:17 ak1 Exp $

class UdpConfigEntry<ConfigEntry

  def initialize(module_file, src_re, dst_re)
    super(module_file,src_re,dst_re)
  end

  def match(src_str,dst_str)
    super(src_str,dst_str)
  end

  def get_module
    super
    UdpModule.new
  end

end
