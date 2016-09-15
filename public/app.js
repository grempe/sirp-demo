/* global $, jsrp */

function resetUI () {
  $('#statusP0').html('')
  $('#statusP1').html('')
  $('#statusP2').html('')
  $('#loginMessage').html('')
  $('#regMessage').html('')
}

function registerUser (username, password) {
  var client = new jsrp.client()

  resetUI()

  // debug
  // var a = new Uint8Array('60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393', 'hex')
  // client.debugInit({ username: username, password: password, length: 4096, a: a }, function () {
  client.init({ username: username, password: password }, function () {
    client.createVerifier(function (err, result) {
      if (err) {
        console.error(err.stack)
      }

      $('#statusP0').append('P0 : START\n')
      $('#statusP0').append('P0 : username : ' + username + '\n')
      $('#statusP0').append('P0 : password : ******\n')
      $('#statusP0').append('P0 : salt : ' + result.salt + '\n')
      $('#statusP0').append('P0 : verifier : ' + result.verifier + '\n')

      $('#statusP0').append('P0 : POST username, salt, and verifier registration data to server\n')
      $.post('/users', { username: username, salt: result.salt, verifier: result.verifier }, function (data) {
        $('#regMessage').html('REGISTERED')

        $('#statusP0').append('P0 : Server returned user.username: ' + data.user.username + '\n')
        $('#statusP0').append('P0 : Server returned user.salt: ' + data.user.salt + '\n')
      }, 'json')
      .fail(function () {
        $('#statusP0').append('P0 : ERROR : User registration failed! Duplicate user?\n')
      })
    })
  })
}

function loginUser (username, password) {
  var client = new jsrp.client()

  resetUI()

  // debug
  // var a = new Uint8Array('60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393', 'hex')
  // client.debugInit({ username: username, password: password, length: 4096, a: a }, function () {
  client.init({ username: username, password: password }, function () {
    // Phase 1
    // Send : username and A
    // Receive : salt and B
    // Calculate : M
    //
    var A = client.getPublicKey()
    $('#statusP1').append('P1 : client A : ' + A + '\n')

    $('#statusP1').append('P1 : Sending username and A to server\n')

    $.post('/challenge', { username: username, A: A }, function (data) {
      $('#statusP1').append('P1 : Received salt : ' + data.salt + '\n')
      client.setSalt(data.salt)
      $('#statusP1').append('P1 : Received B : ' + data.B + '\n')
      client.setServerPublicKey(data.B)

      $('#statusP1').append('P1 : calc M : A : ' + client.ABuf.toString('hex') + '\n')
      $('#statusP1').append('P1 : calc M : B : ' + client.BBuf.toString('hex') + '\n')
      $('#statusP1').append('P1 : calc M : S : ' + client.SBuf.toString('hex') + '\n')
      $('#statusP1').append('P1 : calc M : K : ' + client.KBuf.toString('hex') + '\n')

      var clientM = client.getProof()
      $('#statusP1').append('P1 : calculated client M : ' + clientM + '\n')

      // Phase 2
      // Send : username and M
      // Receive : H_AMK
      // Confirm client and server H_AMK values match, use shared key K
      //
      $('#statusP2').append('P2 : Sending username and client M to server\n')

      $.post('/authenticate', { username: username, M: clientM }, function (data) {
        $('#statusP2').append('P2 : Received server H_AMK : ' + data.H_AMK + '\n')

        if (client.checkServerProof(data.H_AMK)) {
          $('#statusP2').append('P2 : H_AMK values match!\n')
          $('#statusP2').append('P2 : Shared Secret K : ' + client.getSharedKey() + '\n')
          $('#loginMessage').html('AUTHENTICATED')
        } else {
          $('#statusP2').append('P2 : ERROR : Auth Failed : Client and server H_AMK did not match.')
        }
      }, 'json')
      .fail(function () {
        $('#statusP1').append('P2 : ERROR : Attempt to authenticate failed. Unknown user?\n')
      })
    }, 'json')
    .fail(function () {
      $('#statusP1').append('P1 : ERROR : Attempt to authenticate failed. Unknown user?\n')
    })
  })
}

$(document).ready(function () {
  'use strict'

  $('#regButton').click(function () {
    registerUser($('#regUsername').val(), $('#regPassword').val())
  })

  $('#loginButton').click(function () {
    loginUser($('#loginUsername').val(), $('#loginPassword').val())
    // loginUser('leonardo', 'icnivad')
  })
})
