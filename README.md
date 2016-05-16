# SiRP Demo

## Secure (interoperable) Remote Password Protocol (SRP-6a)

This is the code for a live demo version of the [SiRP Ruby Gem](https://github.com/grempe/sirp)

You can try out an interactive version of this demo code at [https://sirp-demo.herokuapp.com/index.html](https://sirp-demo.herokuapp.com/index.html)

## Development

```
$ git clone https://github.com/grempe/sirp-demo.git
$ cd sirp-demo
$ bundle install
$ bundle exec rackup
```
Open [http://localhost:9292](http://localhost:9292) in your browser.

## Ruby Client Sample

There is also a simple Ruby `client.rb` file in the root of this repository
as well.  You can try it out by first running the development server as shown
above in one terminal window, and then run `./client.rb` in a second terminal.
