const reportRoutes = require('./report_routes');

module.exports = function(app, db) {
  reportRoutes(app, db);
  // Other route groups could go here, in the future
};
