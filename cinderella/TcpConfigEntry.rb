# $Id: TcpConfigEntry.rb,v 1.2 2003/06/03 21:21:16 ak1 Exp $

class TcpConfigEntry<ConfigEntry

  def initialize(module_file , src_re , dst_re)
    super(module_file, src_re, dst_re)
  end

  def match(src_str,dst_str)
    super(src_str,dst_str)
  end

  def get_module
    super
    TcpModule.new
  end
end
