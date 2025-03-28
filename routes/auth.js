var express = require('express');
var router = express.Router();
let userController = require('../controllers/users');
const { check_authentication } = require('../Utils/check_auth');

router.post('/signup', async function(req, res, next) {
    try {
        let body = req.body;
        let result = await userController.createUser(
          body.username,
          body.password,
          body.email,
         'user'
        )
        res.status(200).send({
          success:true,
          data:result
        })
      } catch (error) {
        next(error);
      }
})

router.post('/login', async function(req, res, next) {
  try {
      let username = req.body.username;
      let password = req.body.password;
      let result = await userController.checkLogin(username, password);
      res.status(200).send({
          success: true,
          data: result
      });
  } catch (error) {
      next(error);
  }
});

router.get('/me', check_authentication, async function(req, res, next){
    try {
      res.status(200).send({
        success:true,
        data:req.user
    })
    } catch (error) {
        next(error);
    }
})

// Route reset password (chỉ admin)
router.get('/resetPassword/:id', check_authentication, async function(req, res, next) {
    try {
        // Kiểm tra xem user hiện tại có phải admin không
        if (req.user.role !== 'admin') {
            return res.status(403).send({
                success: false,
                message: 'Only admin can reset password'
            });
        }

        const userId = req.params.id;
        const newPassword = '123456';
        
        // Gọi hàm update password từ controller
        let result = await userController.updatePassword(userId, newPassword);
        
        res.status(200).send({
            success: true,
            message: 'Password has been reset to 123456',
            data: result
        });
    } catch (error) {
        next(error);
    }
});

// Route đổi password
router.post('/changePassword', check_authentication, async function(req, res, next) {
    try {
        const { currentPassword, newPassword } = req.body;
        
        // Kiểm tra currentPassword có khớp với password hiện tại không
        const isMatch = await userController.verifyPassword(req.user.id, currentPassword);
        if (!isMatch) {
            return res.status(400).send({
                success: false,
                message: 'Current password is incorrect'
            });
        }

        // Update password mới
        let result = await userController.updatePassword(req.user.id, newPassword);
        
        res.status(200).send({
            success: true,
            message: 'Password has been changed successfully',
            data: result
        });
    } catch (error) {
        next(error);
    }
});

module.exports = router;