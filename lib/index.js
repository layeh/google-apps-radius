/*
 * Copyright (C) 2014 Tim Cooper
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

var dgram = require('dgram');

var radius = require('radius');
var Zombie = require('zombie');

/**
 * Creates a datagram socket that handles RADIUS Access-Request messages.
 *
 * object `options`
 *  string `domain`   - the Google apps domain name
 *  string `secret`   - the radius secret
 *  string `protocol` - "udp4" (default) or "udp6"
 *
 * The additional event "radius" will be emitted by the returned socket object
 * when authentication of a user has completed. The following object will be
 * passed with the event:
 *
 * object `event`
 *  string `username` - the username
 *  string `domain`   - the domain of the user
 *  boolean `status`  - true if accepted, false otherwise
 */
module.exports.createServer = function (options) {
  // Defaults
  if (!options) {
    options = {};
  }
  if (!options.protocol) {
    options.protocol = 'udp4';
  }

  // Create server
  var server = dgram.createSocket(options.protocol);

  // Register callback
  server.on('message', function (msg, rinfo) {
    try {
      var packet = radius.decode({
        packet: msg,
        secret: options.secret
      });
    } catch (ex) {
      return;
    }

    if (packet.code != 'Access-Request') {
      return;
    }

    var username = packet.attributes['User-Name'];
    var password = packet.attributes['User-Password'];

    // Reply function
    var reply = function (status) {
      code = status ? 'Access-Accept' : 'Access-Reject';
      response = radius.encode_response({
        packet: packet,
        code: code,
        secret: options.secret
      });
      server.send (response, 0, response.length, rinfo.port, rinfo.address, function() {
        server.emit('radius', {
          username: username,
          domain: options.domain,
          status: status
        });
      });
    };

    // Test credentials
    try {
      var browser = new Zombie({
        maxRedirects: 20,
        runScripts: false,
        loadCSS: false
      });
      browser.visit('https://accounts.google.com/', function() {
        try {
          browser.fill('#Email', username + '@' + options.domain);
          browser.fill('#Passwd', password);
          browser.pressButton('#signIn', function () {
            var authed = browser.cookies.select({domain: 'google.com', name: 'SID'}).length > 0;
            reply(authed)
          });
        } catch (ex) {
          reply(false);
        }
      });
    } catch (ex) {
      reply(false);
    }
  });

  return server;
};
