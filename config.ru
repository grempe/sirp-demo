#\ -s puma
# ^^^ run puma by default when 'bundle exec rackup'
# or
# bundle exec puma -t 8:32 -w 2 --preload --control tcp://127.0.0.1:9293 --control-token myapp
#
# Access admin with commands [stop, halt, restart]:
# http://localhost:9293/restart?token=myapp

require 'rubygems'
require 'bundler'

Bundler.require

require './app'
run Sinatra::Application
