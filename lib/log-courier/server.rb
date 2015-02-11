# encoding: utf-8

# Copyright 2014 Jason Woods.
#
# This file is a modification of code from Logstash Forwarder.
# Copyright 2012-2013 Jordan Sissel and contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'log-courier/event_queue'
require 'multi_json'
require 'thread'
require 'zlib'

class NativeException; end

module LogCourier
  class TimeoutError < StandardError; end
  class ShutdownSignal < StandardError; end
  class ProtocolError < StandardError; end

  # Implementation of the server
  class Server
    attr_reader :port

    def initialize(options = {})
      @options = {
        logger:    nil,
        transport: 'tls'
      }.merge!(options)

      @logger = @options[:logger]
      @logger['plugin'] = 'input/courier' unless @logger.nil?

      case @options[:transport]
      when 'tcp', 'tls'
        require 'log-courier/server_tcp'
        @server = ServerTcp.new(@options)
      when 'plainzmq', 'zmq'
        require 'log-courier/server_zmq'
        @server = ServerZmq.new(@options)
      else
        fail 'input/courier: \'transport\' must be tcp, tls, plainzmq or zmq'
      end

      # Grab the port back and update the logger context
      @port = @server.port
      @logger['port'] = @port unless @logger.nil?

      # Load the json adapter
      @json_adapter = MultiJson.adapter.instance
      @json_options = { raw: true }
    end

    def run(&block)
      # Receive messages and process them
      @server.run do |signature, message, comm|
        case signature
        when 'PING'
          process_ping message, comm
        when 'JDAT'
          yield(Proc.new do |&block|
            process_jdat message, comm, &block
          end) # Yield now indicates a spool of events, not individuals.
        else
          if comm.peer.nil?
            @logger.warn 'Unknown message received', :from => 'unknown' unless @logger.nil?
          else
            @logger.warn 'Unknown message received', :from => comm.peer unless @logger.nil?
          end
          # Don't kill a client that sends a bad message
          # Just reject it and let it send it again, potentially to another server
          comm.send '????', ''
        end
      end
      return
    end

    private

    def process_ping(message, comm)
      # Size of message should be 0
      if message.length != 0
        fail ProtocolError, "unexpected data attached to ping message (#{message.length})"
      end

      # PONG!
      # NOTE: comm.send can raise a Timeout::Error of its own
      comm.send 'PONG', ''
      return
    end

    def process_jdat(message, comm)
      # OK - first is a nonce - we send this back with sequence acks
      # This allows the client to know what is being acknowledged
      # Nonce is 16 so check we have enough
      if message.length < 17
        fail ProtocolError, "JDAT message too small (#{message.length})"
      end

      nonce = message[0...16]

      if !@logger.nil? && @logger.debug?
        nonce_str = nonce.each_byte.map do |b|
          b.to_s(16).rjust(2, '0')
        end
      end

      # The remainder of the message is the compressed data block
      message = StringIO.new Zlib::Inflate.inflate(message[16...message.length])

      # Message now contains JSON encoded events
      # They are aligned as [length][event]... so on
      # We acknowledge them by their 1-index position in the stream
      length_buf = ''
      data_buf = ''
      loop do
        ret = message.read 4, length_buf
        if ret.nil?
          # Finished!
          break
        elsif length_buf.length < 4
          fail ProtocolError, "JDAT length extraction failed (#{ret} #{length_buf.length})"
        end

        length = length_buf.unpack('N').first

        # Extract message
        ret = message.read length, data_buf
        if ret.nil? or data_buf.length < length
          @logger.warn()
          fail ProtocolError, "JDAT message extraction failed #{ret} #{data_buf.length}"
        end

        data_buf.force_encoding('utf-8')

        # Ensure valid encoding
        unless data_buf.valid_encoding?
          data_buf.chars.map do |c|
            c.valid_encoding? ? c : "\xEF\xBF\xBD"
          end
        end

        # Decode the JSON
        begin
          event = @json_adapter.load(data_buf, @json_options)
        rescue MultiJson::ParseError => e
          @logger.warn e, :hint => 'JSON parse failure, falling back to plain-text' unless @logger.nil?
          event = { 'message' => data_buf }
        end

        # Add peer fields?
        comm.add_fields event

        # Queue the event
        yield(event, Proc.new do |sequence|
          @logger.debug 'Acknowledging message', :nonce => nonce_str.join, :sequence => sequence if !@logger.nil? && @logger.debug?
          comm.send 'ACKN', [nonce, sequence].pack('A*N')
        end)

      end

      return
    end
  end
end
