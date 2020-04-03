const express = require("express")
const User = require("./../models/user")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const crypto = require("crypto")
const mailer = require("./../../modules/mailer")
const authConfig = require("./../../config/auth")

const router = express.Router()

function generateToken(params = {}) {
  return jwt.sign(params, authConfig.secret, {
    expiresIn: 86400,
  })
}

router.post("/register", async (req, res) => {
  const { email } = req.body

  try {
    if (await User.findOne({ email })) {
      return res
        .status(400)
        .send({ message: "users exists with this email", error: {} })
    }
    const user = await User.create(req.body)
    user.password = undefined
    return res.send({ user, token: generateToken({ id: user.id }) })
  } catch (err) {
    return res.status(400).send({ message: "registration failed", error: err })
  }
})

router.post("/authenticate", async (req, res) => {
  const { email, password } = req.body
  const user = await User.findOne({ email }).select("+password")
  if (!user) {
    return res.status(400).send({ message: "User not found", error: {} })
  }
  if (!(await bcrypt.compare(password, user.password))) {
    return res.status(400).send({ message: "Invalid password", error: {} })
  }

  user.password = undefined
  res.send({ user, token: generateToken({ id: user.id }) })
})

router.post("/forgot_password", async (req, res) => {
  const { email } = req.body
  try {
    const user = await User.findOne({ email })

    if (!user) {
      return res.status(400).send({ message: "User not found", error: {} })
    }

    const token = crypto.randomBytes(20).toString("hex")
    const expire = new Date()
    expire.setHours(expire.getHours() + 1)

    User.updateOne()

    await User.findOneAndUpdate(
      { email: user.email },
      {
        passwordResetToken: token,
        passwordResetExpires: expire,
      },
      { useFindAndModify: false }
    )

    mailer.sendMail(
      {
        to: email,
        from: "leandro.souara.web@gmail.com",
        template: "auth/forgot_password",
        context: { token },
      },
      (err) => {
        if (err) {
          return res
            .status(400)
            .send({ message: "cannot send forgot password mail", error: err })
        }
        return res.send()
      }
    )
  } catch (err) {
    res.status(400).send({ message: "Error on forgot password", error: err })
  }
})

router.post("/reset_password", async (req, res) => {
  const { email, token, password } = req.body

  try {
    const user = await User.findOne({ email }).select(
      "+passwordResetToken passwordResetExpires"
    )
    if (!user) {
      return res.status(400).send({ message: "User not found", error: {} })
    }

    if (token != user.passwordResetToken) {
      return res
        .status(400)
        .send({ message: "Invalid token to reset password", error: {} })
    }

    const dateNow = Date()
    if (dateNow > user.passwordResetExpires) {
      return res.status(400).send({ message: "Token Expired", error: {} })
    }

    user.password = password
    await user.save()
    res.send()
  } catch (err) {
    res.status(400).send({ message: "Error on reset password", error: err })
  }
})

module.exports = (app) => app.use("/auth", router)
