#!/usr/bin/env ruby
# encoding: utf-8

require 'rubygems'
require 'bundler/setup'
require 'sinatra'
require 'json'
require 'hashie'
require 'ohm'
require 'ohm/json'
require 'ohm/contrib'
require 'sirp'
require 'logger'
logger = Logger.new $stdout

include Hashie::Extensions::SymbolizeKeys

# Sinatra : Use Puma
configure { set :server, :puma }

set :public_folder, 'public'

# Set prime N length - client has to use the same value!
prime_length = 4096

if ENV['REDIS_URL']
  Ohm.redis = Redic.new(ENV['REDIS_URL'])
end

# Empty redis on each server reload except in prod.
unless ENV['REDIS_URL']
  Ohm.flush
end

class User < Ohm::Model
  include Ohm::DataTypes

  attribute :username
  attribute :salt
  attribute :verifier
  attribute :proof, Type::Hash
  unique :username
  unique :salt
  unique :verifier
  index :username

  # by default to_hash only returns id
  def to_hash
    super.merge(username: username, salt: salt)
  end
end

# Create one user for us to work with.
unless User.find(username: 'leonardo').first
  User.create(SIRP::Verifier.new(4096).generate_userauth('leonardo', 'icnivad')).save
end

before do
  content_type 'application/json'
end

get '/' do
  redirect '/index.html'
end

# empty the test db
get '/flush' do
  Ohm.flush
  redirect '/index.html'
end

post '/users' do
  if params[:username] && params[:username] =~ /^[a-zA-Z0-9\.\@]+$/ && params[:salt] && params[:verifier]
    if User.find(username: params[:username]).first
      logger.warn "Username #{params[:username]} already exists"
      halt 400, JSON.generate(msg: 'user conflict')
    end

    u = User.create(username: params[:username], salt: params[:salt], verifier: params[:verifier]).save
    return JSON.generate(user: u.to_hash)
  else
    halt 400, JSON.generate(msg: 'missing parameters')
  end
end

get '/users/:username' do
  if params[:username] && params[:username] =~ /^[a-zA-Z0-9\.\@]+$/
    user = User.find(username: params[:username]).first

    if user && user.salt && user.proof['B']
      return JSON.generate(salt: user.salt, B: user.proof['B'])
    end

    halt 404, JSON.generate(msg: 'user not found')
  end
end

post '/challenge' do
  if params[:username] && params[:username] =~ /^[a-zA-Z0-9\.\@]+$/
    user = User.find(username: params[:username]).first

    unless user && user.username && user.salt && user.verifier
      halt 404, JSON.generate(msg: 'user not found')
    end
  else
    halt 400, JSON.generate(msg: 'username parameter must be present and valid')
  end

  unless params[:A] && params[:A] =~ /^[a-fA-F0-9]+$/
    halt 400, JSON.generate(msg: 'A parameter must be present and valid')
  end

  logger.info 'P1 : Starting'
  logger.info "P1 : Server received username '#{user.username}' and A"
  logger.info "P1 : Client A : #{params[:A]}"

  # Server generates B, saves A and B to database
  verifier = SIRP::Verifier.new(prime_length)
  session = verifier.get_challenge_and_proof(user.username, user.verifier, user.salt, params[:A])

  logger.info 'P1 : Server persisting user proof to DB'
  user.proof = session[:proof]
  user.save

  logger.info 'P1 : Server sending salt and B'
  logger.info "P1 : Server salt : #{session[:challenge][:salt].length} : #{session[:challenge][:salt]}"
  logger.info "P1 : Server B : #{session[:challenge][:B].length} : #{session[:challenge][:B]}"
  return JSON.generate(session[:challenge])
end

post '/authenticate' do
  if params[:username] && params[:username] =~ /^[a-zA-Z0-9\.\@]+/
    user = User.find(username: params[:username]).first

    unless user && user.username && user.salt && user.verifier
      halt 404, JSON.generate(msg: 'user not found')
    end
  else
    halt 400, JSON.generate(msg: 'username parameter must be present and valid')
  end

  unless params[:M] && params[:M] =~ /^[a-fA-F0-9]+$/
    halt 400, JSON.generate(msg: 'M parameter must be present and valid')
  end

  logger.info 'P2 : Starting'
  logger.info "P2 : Server received username '#{user.username}' and client M"
  client_M = params[:M]
  logger.info "P2 : Client M : #{client_M.length} : #{client_M}"

  logger.info 'P2 : Retrieving proof from the database'
  proof = Hashie.symbolize_keys(user.proof)

  logger.info 'P2 : Verifying client/server M match, generating H_AMK'
  verifier = SIRP::Verifier.new(prime_length)
  server_H_AMK = verifier.verify_session(proof, client_M)

  logger.info "P2 : server A: #{verifier.A}"
  logger.info "P2 : server B: #{verifier.B}"
  logger.info "P2 : server S: #{verifier.S}"
  logger.info "P2 : server K: #{verifier.K}"
  logger.info "P2 : server M: #{verifier.M}"

  if server_H_AMK
    logger.info "P2 : #{user.username} Authenticated!"
    logger.info "P2 : Client and server negotiated shared key K : #{verifier.K}"
    logger.info "P2 : Server sending final H_AMK : #{server_H_AMK.length} : #{server_H_AMK}"
    return JSON.generate(H_AMK: server_H_AMK)
  end

  halt 401, JSON.generate(msg: 'unauthorized')
end
