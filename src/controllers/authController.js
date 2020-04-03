const express = require("express")
const User = require("./../models/user")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const authConfig = require("./../config/auth")

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

module.exports = (app) => app.use("/auth", router)
