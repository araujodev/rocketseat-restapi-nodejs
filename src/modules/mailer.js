const path = require("path")
const nodemailer = require("nodemailer")
const { host, port, user, pass } = require("./../config/mail")
const hbs = require("nodemailer-express-handlebars")

const transport = nodemailer.createTransport({
  host,
  port,
  auth: {
    user,
    pass,
  },
})

transport.use(
  "compile",
  hbs({
    /*viewEngine: 'handlebars',
  viewPath: path.resolve('./src/resources/mail/'),
  extName: '.html',*/

    viewEngine: {
      extName: ".html",
      partialsDir: path.resolve("./src/resources/mail/"),
      layoutsDir: path.resolve("./src/resources/mail/"),
      defaultLayout: "auth/forgot_password.html",
    },
    viewPath: path.resolve("./src/resources/mail/"),
    extName: ".html",
  })
)

module.exports = transport
