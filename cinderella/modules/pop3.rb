# $Id: pop3.rb,v 1.1 2003/06/03 11:13:26 ak1 Exp $
# POP3 module
# (c) 2003 Andreas Krennmair <ak@synflood.at>

# beware: the regular expressions in this module are
# cargo cult programming at its best. *puke*
# (why does /.{1,3}$/m match on '\r\n' but not /.{1,2}$/, /.{2,3}$/ or /..$/ ?)

class TcpModule

  def initialize
    $logger.debug "POP3Module#initialize: doing nothing"
  end

  def evaluate(conv)

    conv.shift # now, THIS is ugly

    $logger.debug "POP3Module#evaluate entering evaluate"
    retval = [ false, true ] # not evaluated, but good (so far)
    multi_line = false

    conv.each_index do |i|
      $logger.debug "POP3Module#evaluate: index is #{i}"
      if (i%2)==0 then # responses from the server
        $logger.debug "POP3Module#evaluate: got server response"
        if multi_line then
          $logger.debug "POP3Module#evaluate: got multiline response"
          multi_line = false
          if not (conv[i] =~ /^\+OK/ or conv[i] =~ /^-ERR/) then
            retval[0] = true
            retval[1] = false
          end
        else
          $logger.debug "POP3Module#evaluate: server response is #{conv[i].dump}"
          if not (conv[i] =~ /^\+OK( ?.{0,508})?$/m or conv[i] =~ /^-ERR( ?.{1,507})?$/m) then
            $logger.debug "POP3Module#evaluate: ...which is evil"
            retval[0] = true
            retval[1] = false
            return retval
          end
        end
      else # commands from the client
        $logger.debug "POP3Module#evaluate: got client command '#{conv[i].dump}'"
        if conv[i] =~ /^RETR \d+.{1,3}$/im or conv[i] =~ /^TOP \d+ \d+.{1,3}$/im or
           conv[i] =~ /^UIDL( \d+)?.{1,3}$/im then
          multi_line = true
          $logger.debug "POP3Module#evaluate: got command with multiline response"
        else
          case conv[i]
            when /^USER .+$/im then
              $logger.debug "POP3Module#evaluate: got USER command"
            when /^PASS .+$/im then
              $logger.debug "POP3Module#evaluate: got PASS command"
            when /^STAT.{1,3}$/im then
              $logger.debug "POP3Module#evaluate: got STAT command"
            when /^LIST( \d+)?.{1,3}$/im then
              $logger.debug "POP3Module#evaluate: got LIST command"
            when /^DELE \d+.{1,3}$/im then
              $logger.debug "POP3Module#evaluate: got DELE command"
            when /^NOOP.{1,3}$/im then
              $logger.debug "POP3Module#evaluate: got NOOP command"
            when /^QUIT.{1,3}$/im then
              retval[0] = true # we are done, but don't quit, there may be an evil '+OK'
              $logger.debug "POP3Module#evaluate: got QUIT command"
            when /^RSET.{1,3}$/im then
              $logger.debug "POP3Module#evaluate: got RSET command"
            when /^UIDL( \d+)?.{1,3}$/im then
              $logger.debug "POP3Module#evaluate: got UIDL command"
            when /^APOP .+ .+$/im then
              $logger.debug "POP3Module#evaluate: got APOP command"
          else
            retval[0] = true
            retval[1] = false
            $logger.debug "POP3Module#evaluate: oh, oh, I don't know this command, so it must be evil."
            return retval
            $logger.debug "POP3Module#evaluate: XXX, I DO NOT RETURN"
          end
        end
      end
    end

    $logger.debug "POP3Module#evaluate: evaluation finished, so far"
    retval
  end

end
