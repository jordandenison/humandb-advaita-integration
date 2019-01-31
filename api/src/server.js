require('app-module-path').addPath(__dirname);

// server.js
const express        = require('express');
const bodyParser     = require('body-parser');
const app            = express();
const port           = process.env.PORT || 5500;

app.use(bodyParser.urlencoded({ extended: true }));

require('./routes')(app, {});
app.listen(port, () => {
  console.log('Advaitabio API listening on port ' + port);
});
