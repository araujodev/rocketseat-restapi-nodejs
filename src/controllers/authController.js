const express = require("express")
const User = require("./../models/user")
const router = express.Router()

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
    return res.send({ user })
  } catch (err) {
    return res.status(400).send({ message: "registration failed", error: err })
  }
})

module.exports = (app) => app.use("/auth", router)
