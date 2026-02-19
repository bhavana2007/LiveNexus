import jwt from "jsonwebtoken";

export const generateToken = (userId,res) => {
    const token = jwt.sign({ id: userId }, process.env.JWT_SECRET, {
        expiresIn: "7d",
    });

    res.cookie("jwt",token,{
        maxAge: 7 * 24 * 60 * 60 * 1000, 
        httpOnly:true,
        sameSite:"strict",
        secure:process.env.NODE_ENV === "production"? true : false,
    });
    
    return token;
};

export const verifyToken = (req, res, next) => {
    try {
        const token = req.cookies.jwt;
        
        if(!token) {
            return res.status(401).json({message: "No token provided"});
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch(error) {
        console.log("Error in verifyToken:", error.message);
        res.status(401).json({message: "Invalid token"});
    }
};