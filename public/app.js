function registerUser (username, password) {
  var client = new jsrp.client()

  $('#statusP0').html('')

  client.init({ username: username, password: password }, function () {
    client.createVerifier(function (err, result) {
      if (err) {
        console.error(err.stack)
      }

      $('#statusP0').append('P0 : START\n')
      $('#statusP0').append('P0 : username : ' + username + '\n')
      $('#statusP0').append('P0 : password : ' + password + '\n')
      $('#statusP0').append('P0 : salt : ' + result.salt + '\n')
      $('#statusP0').append('P0 : verifier : ' + result.verifier + '\n')

      $('#statusP0').append('P0 : POST username, salt, and verifier registration data to server\n')
      $.post('/users', { username: username, salt: result.salt, verifier: result.verifier }, function (data) {
        $('#statusP0').append('P0 : User registration successful\n')
        $('#statusP0').append('P0 : Server returned user.username: ' + data.user.username + '\n')
        $('#statusP0').append('P0 : Server returned user.salt: ' + data.user.salt + '\n')
      }, 'json')
      .fail(function() {
        $('#statusP0').append('P0 : ERROR : User registration failed! Duplicate user?\n')

      })
    })
  })
}

function loginUser (username, password) {
  var client = new jsrp.client()

  $('#statusP1').html('')
  $('#statusP2').html('')

  client.init({ username: username, password: password }, function () {
    // Phase 1
    // Send : username and A
    // Receive : salt and B
    // Calculate : M
    //
    var A = client.getPublicKey()
    $('#statusP1').append('P1 : client A : ' + A + '\n')

    $('#statusP1').append('P1 : Sending username and A to server\n')

    $.post('/authenticate', { username: username, A: A }, function (data) {
      $('#statusP1').append('P1 : Received salt : ' + data.salt + '\n')
      client.setSalt(data.salt)
      $('#statusP1').append('P1 : Received B : ' + data.B + '\n')
      client.setServerPublicKey(data.B)

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
          $('#statusP2').append('\nAUTHENTICATED!')
        } else {
          $('#statusP2').append('P2 : ERROR : Auth Failed : Client and server H_AMK did not match.')
        }
      }, 'json')
    }, 'json')
  })
}

$(document).ready(function () {
  'use strict'

  $('#regButton').click(function () {
    registerUser($('#regUsername').val(), $('#regPassword').val())
  })

  $('#loginButton').click(function () {
    loginUser($('#loginUsername').val(), $('#loginPassword').val())
  })
})
