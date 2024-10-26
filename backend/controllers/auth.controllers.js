import bcryptjs from "bcrypt"
import User from "../models/user.model.js";
import generateTokenAndSetCookie from "../utils/generateToken.js";

export const signup = async (req, res) => {
  try {
    // request input from user
    const {fullName, username, password, confirmPassword, gender} = req.body;

    // check if users password match or not
    if(password !== confirmPassword){
      return res.status(400).json({error:"password don't match"});
    }

    // check if user already exists
    const user = await User.findOne({username});

    if(user){
      return res.status(400).json({error:"user already exists"});
    }

    // Hash password
    const salt = await bcryptjs.genSalt(10);
    const hashPassword = await bcryptjs.hash(password, salt);

    // assign profilePic according to genders
    const boyProfilePic = `https://avatar.iran.liara.run/public/boy?username=${username}`
    const girlProfilePic = `https://avatar.iran.liara.run/public/girl?username=${username}`

    // create the new user
    const newUser = new User({
      fullName,
      username,
      password:hashPassword,
      gender,
      profilePic: gender === "male" ? boyProfilePic : girlProfilePic
    })

    // save the in database
    if (newUser) {
      // Generate JWT token
      generateTokenAndSetCookie(newUser._id, res);
      await newUser.save();

      res.status(201).json({
        _id: newUser._id,
        fullName: newUser.fullName,
        username: newUser.username,
        profilePic: newUser.profilePic
      })
    } else {
      res.status(400).json({error:"Invalid user data"});
    }

  } catch (error) {
    console.log("Error in signup controller", error.message);
    res.status(500).json({error:"Internal server error"})
  }
}

export const login = async (req, res) => {
   try {
    // request input from user
    const {username, password} = req.body;

    // check if user already exists and match the password
    const user = await User.findOne({username});
    const isPasswordCorrect = await bcryptjs.compare(password, user?.password || "");

    if(!user || !isPasswordCorrect) {
      return res.status(400).json({error: "Invalid username or password"});
    }

    // generate the jwt token and send the user in response
    generateTokenAndSetCookie(user._id, res);

    res.status(200).json({
      _id: user._id,
      fullName: user.fullName,
      username: user.username,
      profilePic: user.profilePic,
    })
  
  } catch (error) {
    console.log("Error in login controller", error.message);
    res.status(500).json({error:"Internal server error"})
  }
}

export const logout = (req, res) => {
  try {
    res.cookie("jwt","",{maxAge:0})
    res.status(200).json({message: "Logged out successfully"})
  } catch (error) {
    console.log("Error in logout controller", error.message);
    res.status(500).json({error:"Internal server error"})
  }
}

