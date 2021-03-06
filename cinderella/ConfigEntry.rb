# $Id: ConfigEntry.rb,v 1.1 2003/06/03 21:21:16 ak1 Exp $

class ConfigEntry

  def initialize(module_file , src_re , dst_re)
    $logger.debug "TcpConfigEntry#initialize: #{module_file} #{src_re} #{dst_re}"
    @src_re = Regexp.new(src_re)
    @dst_re = Regexp.new(dst_re)
    @module = module_file
  end

  def match(src_str,dst_str)
    does_match = (nil!=@src_re.match(src_str) and nil!=@dst_re.match(dst_str))
    $logger.debug "ConfigEntry#match: match(#{src_str},#{dst_str}) = #{does_match}"
    does_match
  end

  def get_module
    $logger.debug "ConfigEntry#get_module: loading #{@module}"
    load(@module)
    require(@module)
  end
end
