# $Id: IcmpPolicy.rb,v 1.2 2003/06/24 12:32:59 ak1 Exp $

class IcmpPolicy

  def initialize(src_re,dst_re,pol_list,dir = "oneway")
    @src_re = Regexp.new(src_re)
    @dst_re = Regexp.new(dst_re)
    @codes = Array.new
    @twoway = false
    if dir == "twoway" then
      @twoway = true
    elsif dir == "oneway" then
      @twoway = false
    else
      $logger.warn "IcmpPolicy#initialize: invalid entry for direction: `#{dir}'; setting to oneway"
    end
    19.times { @codes << false } # 0..18 -> 19
    # ...
    icmp_codes = pol_list.split(/,/)
    # the following code could be done nicer
    icmp_codes.each do |code|
      case code
        when 'echoreply' then
          @codes[0] = true
        when 'unreachable' then
          @codes[3] = true
        when 'sourcequench' then
          @codes[4] = true
        when 'redirect' then
          @codes[5] = true
        when 'echo' then
          @codes[8] = true
        when 'routeradvert' then
          @codes[9] = true
        when 'routersolicit' then
          @codes[10] = true
        when 'timxceed' then
          @codes[11] = true
        when 'paramprob' then
          @codes[12] = true
        when 'tstamp' then
          @codes[13] = true
        when 'tstampreply' then
          @codes[14] = true
        when 'ireq' then
          @codes[15] = true
        when 'ireqreply' then
          @codes[16] = true
        when 'maskreq' then
          @codes[17] = true
        when 'maskreply' then
          @codes[18] = true
        else
          $logger.warn "IcmpPolicy#initialize: invalid ICMP message #{m}"
          # ignore invalid entry
        end
    end
  end

  def match_policy(pkt)
    src_str = pkt.ip_src.to_s
    dst_str = pkt.ip_dst.to_s
    code = pkt.icmp_code
    $logger.debug "IcmpPolicy#match_policy: matching packet..."
    if @twoway then
      retval = (nil!=@src_re.match(src_str) and nil!=@dst_re.match(dst_str) and code>=0 and code<=18 and @codes[code])
    else
      retval = ((nil!=@src_re.match(src_str) and nil!=@dst_re.match(dst_str)) or (nil!=@src_re.match(dst_str) and nil!=@dst_re.match(src_str)) and code>=0 and code<=18 and @codes[code])
    end
    retval
  end

end
