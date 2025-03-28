let userSchema = require('../models/users');
let roleSchema = require('../models/roles');
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
let constants = require('../Utils/constants')

module.exports = {
    getUserById: async function(id){
        return await userSchema.findById(id).populate("role");
    },
    
    createUser: async function(username, password, email, role){
        let roleCheck = await roleSchema.findOne({roleName: role});
        if(roleCheck){
            // Hash password trước khi lưu
            const hashedPassword = await bcrypt.hash(password, 10);
            let newUser = new userSchema({
                username: username,
                password: hashedPassword,
                email: email,
                role: roleCheck._id,
            });
            await newUser.save();    
            return newUser;  
        } else {    
            throw new Error("role khong ton tai");
        }
    },
    
    checkLogin: async function(username, password) {
        console.log("Login attempt:", { username, password });
        if (username && password) {
            let user = await userSchema.findOne({ username: username });
            console.log("User found:", user);
            if (user) {
                const passwordMatch = bcrypt.compareSync(password, user.password);
                console.log("Password match:", passwordMatch);
                if (passwordMatch) {
                    return jwt.sign({
                        id: user._id,
                        expired: new Date(Date.now() + 30 * 60 * 1000)
                    }, constants.SECRET_KEY);
                } else {
                    throw new Error("username or password is incorrect");
                }
            } else {
                throw new Error("username or password is incorrect");
            }
        } else {
            throw new Error("username or password is incorrect");
        }
    },

    // Thêm hàm update password
    updatePassword: async function(userId, newPassword) {
        try {
            const user = await userSchema.findById(userId);
            if (!user) {
                throw new Error('User not found');
            }
            // Hash password mới trước khi lưu
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            user.password = hashedPassword;
            await user.save();
            return user;
        } catch (error) {
            throw error;
        }
    },

    // Thêm hàm verify password
    verifyPassword: async function(userId, password) {
        try {
            const user = await userSchema.findById(userId);
            if (!user) {
                throw new Error('User not found');
            }
            return await bcrypt.compare(password, user.password);
        } catch (error) {
            throw error;
        }
    }
}