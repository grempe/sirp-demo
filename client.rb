#!/usr/bin/env ruby
# encoding: utf-8

require 'rubygems'
require 'bundler/setup'
require 'http'
require 'json'
require 'sirp'
require 'logger'
logger = Logger.new $stdout

# FIXME : DEBUG MONKEY-PATCH
module SIRP
  class Client
    def set_a(val)
      @a = val
    end

    def set_h_amk(val)
      @H_AMK = val
    end
  end
end

# USAGE : Pass in the username and password to this
# command as the first and second args.
#
# e.g. ./client.rb foo bar
#
username     = ARGV[0] ||= 'leonardo'
password     = ARGV[1] ||= 'icnivad'

BASE_ADDR  = 'http://localhost:9292'
PRIME_LENGTH = 4096

logger.info 'Start authentication'

client = SIRP::Client.new(PRIME_LENGTH)
# FIXME : DEBUG ONLY : REMOVE
client.set_a('60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393'.to_i(16))
A = client.start_authentication

logger.info "Sending username: '#{username}' and A: '#{A}' to server"

# Client => Server: username, A
# Server => Client: salt, B
resp = HTTP.post(BASE_ADDR + '/challenge', form: { username: username, A: A })
resp_body = resp.parse

logger.info "Server responded with: '#{resp.code} : #{resp_body}'"

exit 1 unless resp.code == 200 && resp_body['salt'] && resp_body['B']

logger.info 'Client is calculating M, from B and salt, as a response to the challenge'
logger.info "Server says salt is : #{resp_body['salt']}"
logger.info "Server says B is : #{resp_body['B']}"
client_M = client.process_challenge(username, password, resp_body['salt'], resp_body['B'])

# Client => Server: username, M
# Server => Client: H(AMK)
logger.info "Client is sending M: '#{client_M}' to server"
resp = HTTP.post(BASE_ADDR + '/authenticate', form: { username: username, M: client_M })
resp_body = resp.parse

logger.info "Server responded with: '#{resp.code} : #{resp_body}'"

exit 1 unless resp.code == 200 && resp_body['H_AMK']

if client.verify(resp_body['H_AMK'])
  logger.info 'Client verification of server H_AMK has succeeded! Authenticated!'
  logger.info "Client and server have negotiated shared secret K: '#{client.K}'"
else
  logger.error 'Client verification of server H_AMK has failed!'
end
