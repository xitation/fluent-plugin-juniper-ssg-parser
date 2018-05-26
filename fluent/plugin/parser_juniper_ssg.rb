require 'fluent/parser'

module Fluent
  class TextParser
    class FirewallParser_ssg < Parser
      # Register this parser as "firewall"
      Fluent::Plugin.register_parser("juniper_ssg", self)
      
      config_param :time_format, :string, default: "%b %e %H:%M:%S"

      def initialize()
        super

        @time = '\w+\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'
        @duration = '\d{1,2}:\d{1,2}:\d{1,2}'
        @ipv6 = '((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?'
        @ipv4 = '(?<![0-9])(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))(?![0-9])'
        @ip = "(?:#@ipv4|#@ipv6)"
        @hostname = '\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\b)'
        @iporhost = "(?:#@ip|#@hostname)"
        @posint = '\b(?:[1-9][0-9]*)\b'
        @hostport = "#@iporhost:#@posint"
        @word = '\b\w+\b'
	      @ext_word = '\S+'
        @data = '.*?'
        @int = '(?:[+-]?(?:[0-9]+))'
        @greedydata = '.*'
        @start_time = '\d{2,4}-\d{1,2}-\d{1,2} \d{1,2}:\d{1,2}:\d{1,2}'

        # Normal allow, excluding icmp or deny
        @r1 = /^(?<time>#@time) (?<dvc_ip>#@iporhost) #@iporhost: NetScreen device_id=(?<dvc_name>#@word)#@data: start_time="(?<start_time>#@start_time)" duration=(?<duration>#@int) policy_id=(?<rule_id>#@int) service=(?<app>#@data) proto=(?<transport>#@int) src zone=(?<src_zone>#@ext_word) dst zone=(?<dest_zone>#@ext_word) action=(?<action>#@word) sent=(?<bytes_out>#@int) rcvd=(?<bytes_in>#@int) src=(?<src_ip>#@iporhost) dst=(?<dest_ip>#@iporhost) src_port=(?<src_port>#@int) dst_port=(?<dest_port>#@int) src-xlated ip=(?<src_translated_ip>#@iporhost) port=(?<src_translated_port>#@int) dst-xlated ip=(?<dest_translated_ip>#@iporhost) port=(?<dest_translated_port>#@int) session_id=(?<session_id>#@int) reason=(?<reason>#@greedydata)/
        # Generic Deny 
        @r2 = /^(?<time>#@time) (?<dvc_ip>#@iporhost) #@iporhost: NetScreen device_id=(?<dvc_name>#@word)#@data: start_time="(?<start_time>#@start_time)" duration=(?<duration>#@int) policy_id=(?<rule_id>#@int) service=(?<app>#@data) proto=(?<transport>#@int) src zone=(?<src_zone>#@ext_word) dst zone=(?<dest_zone>#@ext_word) action=(?<action>#@word) sent=(?<bytes_out>#@int) rcvd=(?<bytes_in>#@int) src=(?<src_ip>#@iporhost) dst=(?<dest_ip>#@iporhost) src_port=(?<src_port>#@int) dst_port=(?<dest_port>#@int) session_id=(?<session_id>#@int) reason=(?<reason>#@greedydata)/
        # ICMP Deny - no nat / x-late
        @r3 = /^(?<time>#@time) (?<dvc_ip>#@iporhost) #@iporhost: NetScreen device_id=(?<dvc_name>#@word)#@data: start_time="(?<start_time>#@start_time)" duration=(?<duration>#@int) policy_id=(?<rule_id>#@int) service=(?<app>#@data) proto=(?<transport>#@int) src zone=(?<src_zone>#@ext_word) dst zone=(?<dest_zone>#@ext_word) action=(?<action>#@word) sent=(?<bytes_out>#@int) rcvd=(?<bytes_in>#@int) src=(?<src_ip>#@iporhost) dst=(?<dest_ip>#@iporhost) icmp type=(?<icmp_type>#@int) icmp code=(?<icmp_code>#@int) session_id=(?<session_id>#@int) reason=(?<reason>#@greedydata)/
        # ICMP Allow - with Nat / x-late
        @r4 = /^(?<time>#@time) (?<dvc_ip>#@iporhost) #@iporhost: NetScreen device_id=(?<dvc_name>#@word)#@data: start_time="(?<start_time>#@start_time)" duration=(?<duration>#@int) policy_id=(?<rule_id>#@int) service=(?<app>#@data) proto=(?<transport>#@int) src zone=(?<src_zone>#@ext_word) dst zone=(?<dest_zone>#@ext_word) action=(?<action>#@word) sent=(?<bytes_out>#@int) rcvd=(?<bytes_in>#@int) src=(?<src_ip>#@iporhost) dst=(?<dest_ip>#@iporhost) icmp type=(?<icmp_type>#@int) icmp code=(?<icmp_code>#@int) src-xlated ip=(?<src_translated_ip>#@iporhost) dst-xlated ip=(?<dest_translated_ip>#@iporhost) session_id=(?<session_id>#@int) reason=(?<reason>#@greedydata)/

        @juniper_regex = Regexp.union(@r1, @r2, @r3, @r4)
      end

      # This method is called after config_params have read configuration parameters
      def configure(conf)
        super

        # TimeParser class is already given. It takes a single argument as the time format
        # to parse the time string with.
        @time_parser = TimeParser.new(@time_format)
      end

      # This is the main method. The input "text" is the unit of data to be parsed.
      # If this is the in_tail plugin, it would be a line. If this is for in_syslog,
      # it is a single syslog message.
      def parse(text)

        unless m = @juniper_regex.match(text)
          yield nil, nil
        else
          record = {}
          time = @time_parser.parse(m['time'])

          m.names.each do |name|
            record[name] = m[name] if m[name]
          end

          yield time, record
        end
      end
    end
  end
end
