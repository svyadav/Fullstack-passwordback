var express = require("express");
var router = express.Router();
const nodemailer=require("nodemailer")
const { mongoose, usersModel } = require("../dbSchema");
const { mongodb, dbName, dbUrl } = require("../dbConfig");
const jwt=require('jsonwebtoken')
const bcrypt = require("bcryptjs");
const {
  hashPassword,
  hashCompare,
  createToken,
  jwtDecode,
  validate,
  roleAdmin,
} = require("../auth");
mongoose.connect(dbUrl);
const keysecret="DIENFIRVNOVNJVNVNVJKN"
// const CLIENT_URL = "https://aquamarine-wisp-e67a11.netlify.app"

//email config
 
const transporter=nodemailer.createTransport({
  service:"gmail",
  auth:{
    user:"ysachin511@gmail.com",
    pass:"mznxwxbykctfzltw"
  }


})

/* GET users listing. */
router.get("/", validate, async (req, res) => {
  let token = req.headers.authorization.split(" ")[1];
  let data = await jwtDecode(token);
  let user = await usersModel.find({ email: data.email });
  if (user.length) {
    let users = await usersModel.find({}, { password: 0, __v: 0 });
    res.send({
      statusCode: 200,
      data: users,
    });
  } else {
    res.send({
      statusCode: 404,
      message: "Unauthorized",
    });
  }
});

router.post("/signup", async (req, res) => {
  try {
    let user = await usersModel.find({ email: req.body.email });
    if (user.length) {
      res.send({
        statusCode: 400,
        message: "User alredy exists",
      });
    } else {
      let hashedPassword = await hashPassword(req.body.password);
      req.body.password = hashedPassword;
      let newUser = await usersModel.create(req.body);
      res.send({
        statusCode: 200,
        message: "Sign up successfull",
      });
    }
  } catch (error) {
    console.log(error);
    res.send({
      statusCode: 500,
      message: "Internal server error",
      error,
    });
  }
});

router.post("/signin", async (req, res) => {
  try {
    let user = await usersModel.find({ email: req.body.email });
    if (user.length) {
      let hash = await hashCompare(req.body.password, user[0].password);
      if (hash) {
        let token = await createToken(user[0].email, user[0].role);
        res.send({
          statusCode: 200,
          message: "Signin successfull",
          token,
        });
      } else {
        res.send({
          statusCode: 400,
          message: "Invalid credentials",
        });
      }
    } else {
      res.send({
        statusCode: 400,
        message: "User does not exists",
      });
    }
  } catch (error) {
    console.log(error);
    res.send({
      statusCode: 500,
      message: "Internal server error",
      error,
    });
  }
});

router.delete("/delete-user/:id", validate, async (req, res) => {
  try {
    let user = await usersModel.find({ _id: mongodb.ObjectId(req.params.id) });
    if (user.length) {
      let users=await usersModel.deleteOne({_id:mongodb.ObjectId(req.params.id)})
      res.send({
        statusCode:200,
        message:"User Deleted successfully"
      })
    } else {
      res.send({
        statusCode: 400,
        message: "User does not exist",
      });
    }
  } catch (error) {
    console.log(error);
    res.send({
      statusCode: 400,
      message: "Internal server error",
      error,
    });
  }
});

router.put("/edit-user/:id",validate,async(req,res)=>{
  try{
    let user = await usersModel.findOne({ _id: mongodb.ObjectId(req.params.id) });
    if(user){
      user.firstName=req.body.firstName
      user.lastName=req.body.lastName
      user.email=req.body.email
      await user.save()
      res.send({
        statusCode:200,
        message:"User Data saved Successfully"
      })


    }
    else{
      res.send({
        statusCode:400,
        message:"User does not exist"
      })
    }

  }
  catch(error){
    console.log(error);
    res.send({
      statusCode: 400,
      message: "Internal server error",
      error,
    });

  }
})

//send reset password link

router.post("/sendpasswordLink",async(req,res)=>{
  console.log(req.body)
  const {email} =req.body

  if(!email){
    res.status(401).json({status:401,message:"Enter your Email"})
  }

  try{
    const userFind=await usersModel.findOne({email:email})
    const token=jwt.sign({_id:userFind._id},keysecret,{
      expiresIn:"120s"
    })
    const setusertoken=await usersModel.findByIdAndUpdate({_id:userFind._id},{verifyToken:token},{new:true});
    if(setusertoken){
      const mailOptions={
        from:"ysachin511@gmail.com",
        to:email,
        subject:"Sending Email for passsword reset",
        text:`This link is valid for two minutes https://aquamarine-nasturtium-af7e94.netlify.app/forgetpassword/${userFind.id}/${setusertoken.verifyToken}`
      }

      transporter.sendMail(mailOptions,(error,info)=>{
        if(error){
          console.log("error",error)
          res.status(401).json({status:401,messsage:"email not send"})
        }
        else{
          console.log("Email send",info.response);
          res.status(201).json({status:201,message:"Email send successfully"})
        }
      })

    }
  }
  catch(error){

    res.status(401).json({status:401,messsage:"Invalid user"})
  }
})


//Verify user for forget time

router.get("/forgetpassword/:id/:token",async(req,res)=>{
  const {id,token}=req.params
  try{
    const validuser=await usersModel.findOne({_id:id,verifyToken:token})
    const verifyTokenn=jwt.verify(token,keysecret)
    if(validuser && verifyTokenn._id){ 
      res.status(201).json({status:201,validuser})

    }
    else{
      res.status(401).json({status:401,message:"user does not exist"})
    }

  }
  catch(error){
    res.status(401).json({status:401,error})

  }

})


//Change password


router.post("/newpass/:id/:token",async(req,res)=>{
  const {id,token} =req.params;
  const {password}=req.body;

  try{
    const validuser=await usersModel.findOne({_id:id,verifyToken:token})
    const verifyTokenn=jwt.verify(token,keysecret)
    if(validuser && verifyTokenn._id){
    const newpassword=await bcrypt.hash(password,12)
    const setnewuserpass=await usersModel.findByIdAndUpdate({_id:id},{password:newpassword})
    setnewuserpass.save()
    res.status(201).json({status:201,setnewuserpass})

    }
    else{
      res.status(401).json({status:401,message:"user does not exist"})
    }

  }
  catch(error){
    res.status(401).json({status:401,error})

  }
})

module.exports = router;
