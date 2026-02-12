const userModel = require("../models/user-model")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const {generateToken} = require("../utils/generateToken")


module.exports.registerUser = async function(req, res){
    try{
        let { email , fullname , password } = req.body;

        let user = await userModel.findOne({email : email})
        if(user) {
            req.flash("error", "User already exists")
            return res.redirect("/")
        }

        bcrypt.genSalt(10 , (err, salt) =>{
            bcrypt.hash(password , salt ,  async (err, hash )=>{
                if(err) {
                    req.flash("error", "Error creating account")
                    return res.redirect("/")
                }
                else {
                    let user = await userModel.create({
                        email , 
                        password : hash , 
                        fullname 
                    })

                    let token = generateToken(user)
                    res.cookie("token" , token )
                    res.redirect("/shop")
                }
            })
        })
    }
    catch(err){
        req.flash("error", err.message)
        res.redirect("/")
    }
}
module.exports.loginUser = async function(req, res){
    try{
        let {email , password} = req.body;
        let user = await userModel.findOne({email : email })
        if(!user) {
            req.flash("error", "Invalid email or password")
            return res.redirect("/")
        }
        
        bcrypt.compare(password , user.password , (err, result) =>{
            if(result){
                let token = generateToken(user)
                res.cookie("token" , token)
                res.redirect("/shop")
            }
            else{
                req.flash("error", "Invalid email or password")
                res.redirect("/")
            }
        })
    }
    catch(err){
        req.flash("error", "Login error occurred")
        res.redirect("/")
    }
}
module.exports.logoutUser = async function(req, res){
    res.cookie("token" , "")
    res.redirect("/")
}