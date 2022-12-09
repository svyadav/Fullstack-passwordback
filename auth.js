const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const saltRound = 10;
const secretkey = "KNINIRVJVFVKJ";

let hashPassword = async (password) => {
  let salt = await bcrypt.genSalt(saltRound);
  let hashedPassword = await bcrypt.hash(password, salt);
  return hashedPassword;
};

let hashCompare = async (password, hashedPassword) => {
  return bcrypt.compare(password, hashedPassword);
};

let createToken = async (email, role) => {
  let token = await jwt.sign({ email, role }, secretkey, { expiresIn: "5m" });
  return token;
};

let jwtDecode = async (token) => {
  let data = await jwt.decode(token);
  return data;
};

let validate = async (req, res, next) => {
  if (req.headers && req.headers.authorization) {
    let token = req.headers.authorization.split(" ")[1];
    let data = await jwtDecode(token);
    let currentTime = Math.round(new Date() / 1000);
    if (currentTime <= data.exp) next();
    else {
      res.send({
        statusCode: 200,
        message: "Token Expired",
      });
    }
  }
  else{
    res.send({
      statusCode:401,
      message:"Invalid Token or No Token"
    })
  }
};

// let roleAdmin = async (req, res, next) => {
//   if (req.headers && req.headers.authorization) {
//     let token = req.headers.authorization.split(" ")[1];
//     let data = await jwtDecode(token);
//     if (data.role === "Admin") next();
//     else {
//         res.send({
//           statusCode: 401,
//           message: "Unauthorised:Only admin can access",
//         });
//       }
//   } 

//   else{
//     res.send({
//       statusCode:401,
//       message:"Invalid"
//     })
//   }
 
// };

module.exports = {
  hashPassword,
  hashCompare,
  createToken,
  jwtDecode,
  validate,
};
