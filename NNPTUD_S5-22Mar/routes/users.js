var express = require("express");
var router = express.Router();
let userController = require("../controllers/users");
let {
  check_authentication,
  check_authorization,
} = require("../utils/check_auth");
let { CreateSuccessRes } = require("../utils/responseHandler");
let constants = require("../utils/constants");
/* GET users listing. */
router.get(
  "/",
  check_authentication,
  check_authorization(constants.MOD_PERMISSION),
  async function (req, res, next) {
    try {
      let users = await userController.GetAllUsers();
      CreateSuccessRes(res, users, 200);
    } catch (error) {
      next(error);
    }
  }
);

router.get("/:id", check_authentication, async function (req, res, next) {
  try {
    // Nếu user xem thông tin của chính mình -> cho phép
    if (req.user._id.toString() === req.params.id) {
      let user = await userController.GetUserByID(req.params.id);
      return CreateSuccessRes(res, user, 200);
    }

    // Nếu không phải xem thông tin của chính mình -> kiểm tra quyền MOD
    if (
      !req.user.role ||
      !constants.MOD_PERMISSION.includes(req.user.role.name)
    ) {
      throw new Error("Bạn không có quyền xem thông tin của user khác");
    }

    let user = await userController.GetUserByID(req.params.id);
    CreateSuccessRes(res, user, 200);
  } catch (error) {
    next(error);
  }
});

router.post(
  "/",
  check_authentication,
  check_authorization(constants.ADMIN_PERMISSION),
  async function (req, res, next) {
    try {
      let body = req.body;
      let user = await userController.CreateAnUser(
        body.username,
        body.password,
        body.email,
        body.role
      );
      CreateSuccessRes(res, user, 200);
    } catch (error) {
      next(error);
    }
  }
);

router.put(
  "/:id",
  check_authentication,
  check_authorization(constants.ADMIN_PERMISSION),
  async function (req, res, next) {
    try {
      let body = req.body;
      let user = await userController.UpdateAnUser(req.params.id, body);
      CreateSuccessRes(res, user, 200);
    } catch (error) {
      next(error);
    }
  }
);

router.delete(
  "/:id",
  check_authentication,
  check_authorization(constants.ADMIN_PERMISSION),
  async function (req, res, next) {
    try {
      let user = await userController.DeleteAnUser(req.params.id);
      CreateSuccessRes(res, user, 200);
    } catch (error) {
      next(error);
    }
  }
);

module.exports = router;
