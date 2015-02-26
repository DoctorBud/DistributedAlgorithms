////////////////////////////////////////////////////////////////////////
// Encryption Examples
//
// A Site's PID is its 'host:port' string.
//
// This file initializes the following services:
//   - HTTP for the purpose of WebUI
//   - HTTP for the purpose of REST API
//   - Discovery
//

// Dependencies
var Path = require('path');
var Util = require('util');
var Discovery = require('./server-discovery.js');
var FS = require('fs');

// Test Harness Configuration
// Not part of the algorithm, but needed to set up the distributed environment
// and participants list.

var configDiscoveryDelay = 8000;
var configGapTimeLow = 100;
var configGapTimeHigh = 2000;
var configWorkTimeLow = 2000;
var configWorkTimeHigh = 5000;
var configCleanupDelay = 5000;
var configSyncLog = 'shared.log';
var configMessageToSign = 'Go Ducks!';

// All my State is living up here at the top of file because
// I'm still in wild-editing mode and don't know where stuff will end up.
// Eventually, I'll tight-scope everything.

var myHost = null;
var myPort = null;
var myPID = null;
var myPIDIndex = -1;

//
// State vars for the RA Algorithm
//
var participantsChosen = false;
var participatingNodes = null;  // List of PIDs discovered before Lockout
                              // Each PID is a URI http://host:port

var stateINIT =             'INIT          ';
var stateSEND_SIGNED =      'SEND_SIGNED   ';
var stateRECEIVE_SIGNED =   'RECEIVE_SIGNED';
var stateSEND_FORGED =      'SEND_FORGED   ';
var stateCLEANUP =          'CLEANUP       ';
var state = stateINIT;


function buildPID(host, port) {
  return 'http://' + host + ':' + port;
}

//
// Synchronous logging to a shared log file (configSyncLog)
//

function padRight(str, len) {
  str = String(str);
  var padLength = len - str.length + 1;
  var result = (padLength > 0) ?
                  str + (Array(padLength).join(' ')) :
                  str;
  return result;
}

function syncLog() {  // uses 'arguments'
  var args = Array.prototype.slice.call(arguments, 0);
  var header = '[' + state + ' ' + myPID + ']';
  var paddedHeader = padRight(header, 40);
  var data = paddedHeader + '   ' + args.join('  ');
  FS.appendFileSync(configSyncLog, data + '\n');
  console.log(data);
}

var request = require('request');


function enterStateCLEANUP() {
  syncLog('enterStateCLEANUP', configCleanupDelay);
  state = stateCLEANUP;
  setTimeout(
    function () {
      syncLog('CLEANUP complete... Exiting process');
      process.exit();
    }, configCleanupDelay);
}


var Crypto = require('crypto');


function keyprint(key) {
  var result = key.substr(50, 8);
  return result;
}

function sigprint(sig) {
  var result = sig.substr(50, 8);
  return result;
}

function handleRECEIVE_SIGNED(msg) {
  syncLog('handleRECEIVE_SIGNED:', msg.path, 'Sender:', msg.query.senderPID, ' Plain:', msg.query.plainText, ' Signature:', sigprint(msg.query.signature));

  var verifier = Crypto.createVerify('sha256');
  var senderPubKey = participatingNodes[0].pubkey;   // Expecting msgs from Node0
  verifier.update(msg.query.plainText);
  var ver = verifier.verify(senderPubKey, msg.query.signature, 'hex');
  if (ver) {
    syncLog('WELCOME!!        ', msg.query.senderPID, ' Signature:', sigprint(msg.query.signature));
  }
  else {
    syncLog('INTRUDER ALERT!!! Posing as:', msg.query.senderPID, ' Signature:', sigprint(msg.query.signature));
  }
}


function handleResponse(error, response, body) {
  if (error || response.statusCode != 200) {
    syncLog('    handleRequestResponse ERROR', error, response, body);
  }

  enterStateCLEANUP();
}


function enterStateRECEIVE_SIGNED() {
  syncLog('enterStateRECEIVE_SIGNED');
  state = stateRECEIVE_SIGNED;
}


function enterStateSEND_SIGNED(target, plainText) {
  syncLog('enterStateSEND_SIGNED', target);
  state = stateSEND_SIGNED;
  var site = target.pid;
  var url = site + '/RECEIVE_SIGNED';
  syncLog('  RECEIVE_SIGNED to ', url);

  var sign = Crypto.createSign('RSA-SHA256');
  sign.update(plainText);
  var signature = sign.sign(mypair.private, 'hex');

  var options = {
      url:      url,
      method:   'GET',
      headers:  {
                    'User-Agent':       'Super Agent/0.0.1',
                    'Content-Type':     'application/x-www-form-urlencoded'
                },
      qs:       {
                    'senderPID': myPID,
                    'plainText': plainText,
                    'signature': signature
                }
  };

  request(options, handleResponse);
}


function enterStateSEND_FORGED(target, validSender, plainText) {
  syncLog('enterStateSEND_SIGNED', target);
  state = stateSEND_SIGNED;
  var site = target.pid;
  var url = site + '/RECEIVE_SIGNED';
  syncLog('  RECEIVE_SIGNED to ', url);

  var impersonateThisPID = validSender.pid;
  var sign = Crypto.createSign('RSA-SHA256');
  sign.update(plainText);
  var signature = sign.sign(mypair.private, 'hex');

  var options = {
      url:      url,
      method:   'GET',
      headers:  {
                    'User-Agent':       'Super Agent/0.0.1',
                    'Content-Type':     'application/x-www-form-urlencoded'
                },
      qs:       {
                    'senderPID': impersonateThisPID,
                    'plainText': plainText,
                    'signature': signature
                }
  };

  request(options, handleResponse);
}


function participantsChanged(nodeList) {
  if (participantsChosen) {
    syncLog('participantsChanged IGNORED. Discover is LOCKED');
  }
  else {
    // Update participatingNodes
    var sortedList = nodeList.slice();
    sortedList.sort(
      function(left, right) {
        return left.advertisement.myPort > right.advertisement.myPort;
      });
    participatingNodes = sortedList.map(
      function(element) {
        var advertisement = element.advertisement;
        var pid = buildPID(advertisement.myHost, advertisement.myPort);
        var nodeInfo =
          {
            pid:    pid,
            pubkey: advertisement.myPubkey
          };
        return nodeInfo;
      });
  }
};

////////////////////////////////////////////////////////////////////////
// PKI Stuff

//
// Keypair stuff
//

var Keypair = require('keypair');
var mypair = Keypair();


function beginSimulation() {
  syncLog('======================================================');
  syncLog('beginSimulation...');
  var validSender = participatingNodes[0];
  var validReceiver = participatingNodes[1];
  var forger = participatingNodes[2];

  if (myPIDIndex === 0) {
    enterStateSEND_SIGNED(validReceiver, configMessageToSign);
  }
  else if (myPIDIndex === 1) {
    enterStateRECEIVE_SIGNED();
  }
  else {
    enterStateSEND_FORGED(validReceiver, validSender, configMessageToSign);
  }
}


////////////////////////////////////////////////////////////////////////
// WebUI and API Stuff


var Hapi = require('hapi');
var server = new Hapi.Server();

server.views({
  engines: {
    html: require('handlebars')
  },
  isCached: false,    // Useful when using livereload
  path: __dirname     // Path.join(__dirname, 'client')
});

// Declare the connection BEFORE the routes
//  To use an explicit port...   server.connection({ port: 8000 });
server.connection();

//
// STATUS, RECEIVE_SIGNED Routes
//

server.route({
    method: 'GET',
    path: '/',
    handler: function (request, reply) {
        var context = {
            host:   myHost,
            port:   myPort,
            pid:    myPID,
            nodes:  participatingNodes
        };

        reply.view('STATUS', context);
    }});

server.route({
    method: 'GET',
    path: '/RECEIVE_SIGNED',
    handler: function (request, reply) {
        handleRECEIVE_SIGNED(request);
        reply.view('RECEIVE_SIGNED');
    }});

//
// Main Server Startup
//
server.start(function () {
  var ip = require('ip');
  myHost = ip.address();
  myPort = server.info.port;
  myPID = buildPID(myHost, myPort);
  syncLog('Server started at: ' + myPID);

  syncLog('### Discovery Initiated for ', configDiscoveryDelay, 'ms');

  var myAdvert =  { myHost :  myHost,
                    myPort :  myPort,
                    myPubkey: mypair.public
                  };

  Discovery.startDiscovery(myAdvert, participantsChanged);

  setTimeout(
    function () {
      participantsChosen = true;
      syncLog('### Discovery Complete and Locked. Participant list is:');

      for (var i = 0; i < participatingNodes.length; ++i) {
        syncLog('   [', i, '] ', participatingNodes[i].pid, keyprint(participatingNodes[i].pubkey));
        if (myPID === participatingNodes[i].pid) {
          myPIDIndex = i;
        }
      }

      beginSimulation();
    }, configDiscoveryDelay ); // Wait 10secs to open all processes.
});
