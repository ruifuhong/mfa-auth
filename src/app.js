const express = require("express");
const cookieParser = require("cookie-parser");
const { openDatabase } = require("./db");

function createApp({ dbPath } = {}) {
  const db = openDatabase(dbPath);
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json());
  app.use(cookieParser());
  app.locals.db = db;
  // Slice routes (signup/login/logout/me) are added in later TDD steps.
  return app;
}

module.exports = { createApp };
