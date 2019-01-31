const feathers = require('@feathersjs/feathers')
const socketio = require('@feathersjs/socketio-client')
const auth = require('@feathersjs/authentication-client')
const io = require('socket.io-client')

const url = process.env.AUTH_API_URL || 'http://hdb-dash-auth:3001/'

const authData = {
  strategy: 'local',
  email: process.env.ADVAITABIO_API_USERNAME || 'test',
  password: process.env.ADVAITABIO_API_PASSWORD || 'test'
}

const socket = io(url, {
  path: '/auth/socket.io',
  transports: ['websocket']
})

const app = feathers()
  .configure(socketio(socket, { timeout: 10000, 'force new connection': true }))
  .configure(auth({ path: '/auth/authenticatasion' }))

let accessToken
app.authenticate(authData)
  .then(res => {
    console.log('Successfully authenticated against auth API ', res)

    accessToken = res.accessToken
  })
  .catch(e => console.log(`Error authenticating against auth API: ${e.message}`))

const getAccessToken = () => accessToken

module.exports = {
  app,
  getAccessToken
}
