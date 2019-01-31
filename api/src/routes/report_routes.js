const fs = require('fs');

const { postMessage } = require('lib/discussion')

module.exports = (app, db) => {

  app.post('/api/advaita/report', async (req, res, next) => {
    // The request body from advaita analytics container
    console.log(req.body)

    fs.readFile(req.body.outputFile, async (err, data) => {
      if (err) { return next(err) }

      try {
        const title = req.body.title
        const { chatBody, json } = await postMessage(title, data)

        res.send('Advaita Ipathways analysis complete. Report posted to discussion board.', chatBody, json)
      } catch (e) {
        console.log(`Error posting message to chat ${e.message}`)

        return next(e)
      }
    });
  });

  app.get('/api/advaita/health', (req, res) => {
    //log the incoming request
    console.log(req.body)
    res.sendStatus(200)
  });

};
