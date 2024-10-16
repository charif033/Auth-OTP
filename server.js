const express = require("express");
const approutes = require("./routes/routes");
const { router: apiroutes } = require("./routes/api");
const cookieParser = require('cookie-parser');

const app = express();
const port = 3000;

app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use('/', approutes);
app.use('/', apiroutes);

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
    console.log(`Go to http://localhost:${port}`);
});