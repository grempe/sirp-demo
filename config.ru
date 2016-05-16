#\ -s puma
# ^^^ run puma by default when 'bundle exec rackup'
# or
# bundle exec puma -t 8:32 -w 2 --preload --control tcp://127.0.0.1:9293 --control-token myapp

require 'rubygems'
require 'bundler'

Bundler.require

require './app'
run Sinatra::Application
