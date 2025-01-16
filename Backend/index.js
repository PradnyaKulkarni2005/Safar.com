const express=require('express')
const app=express()
const path=require('path')
const bodyParser = require('body-parser')
require('dotenv').config();

app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static(path.join(__dirname, '../Frontend')));
const PORT=process.env.PORT || 4000;
const bodyparser=require('body-parser')
const session=require('express-session')
app.use(session({
  secret: 'secret',
  resave: true,
  saveUninitialized: true
})); 

// Database Connection
const mysql=require('mysql')
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

db.connect(err=>{
  if (err) throw err;
  console.log("Connected to the database successfully");
})
// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname,  '../Frontend/index.html'));
  });
app.get('../Frontend/login', (req, res) => {
    res.sendFile(path.join(__dirname,  '../Frontend/login.html'));
  });
app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname,  '../Frontend/signup.html'));
  });
// Signup
const bcrypt=require('bcryptjs')
app.post('/signup',(req,res)=>{
  const {email, password}=req.body;
  const hashedpassword=bcrypt.hashSync(password,10);
  const query='INSERT INTO users(email,password) VALUES(?,?)';
  db.query(query,[email,hashedpassword],(err)=>{
    if(err) throw err;
    res.send('User Registered Successfully !');
  })
});



// Login
require('dotenv').config();
const JWT_SECRET = process.env.JWT_SECRET;

const jwt=require('jsonwebtoken')

app.post('/login',(req,res) =>{
  const {email,password}=req.body;
  const query='SELECT * FROM users WHERE email= ?';
  db.query(query,[email],(err,results)=>{
    if(err) throw err;
    if(results.length >0){
      const user=results[0];
      if(bcrypt.compareSync(password,user.password)){
        // If password matches then generate token
        const token=jwt.sign(
          {id:user.id, email:user.email},// this data is stored in the token
          JWT_SECRET,
          {expiresIn:'1h'}// token will expire in 1 hour
        );
        res.json({message:'Login Successful !',token})
        // alert('Login Successful !')
        // res.sendFile(path.join(__dirname, 'Web_Project', 'home.html'))
      }
      else{
        res.status(401).send('Invalid Password');
      }
    }
    else{
      res.status(404).send('User not found');
    }
  })

})
// Middleware to verify the JWT token
const authenticateJWT=(req,res,next)=>{
  // Extracts token from the authorization header in http req.
  // Authorization header contains string like Bearer<token>
  // req.headers['authorization'] fetches the entire value of the Authorization header.
//   split(' ') splits this string into parts: ["Bearer", "<token>"].
// [1] selects the second part, which is the actual token.
// The ?. ensures that if authorization is undefined, it doesn’t throw an error (avoiding a crash).

  const token = req.headers['authorization']?.split(' ')[1];
  // checks if the token exists and handles the case if the token is undefined or null
  if(!token){
    return res.status(403).send('Access denied.No token provided')
  }
  // verify token
  try{
    // verifies that the token is valid 
    // Takes the token and secret key , decodes the token if it is valid and also ensures it has not been altered.
    // if valid returns the payload data like user details and permissions
    // if invalid throws error
    const decoded=jwt.verify(token,JWT_SECRET);
    // stores the decoded token data in req.user property so that we can access req.user.id further
    req.user=decoded;
    // next passes control to the next middleware
    next();

  }
  // Handle invalid token
  // if token is invalid jwt.verify() will throw an error and the catch func will handle it
  catch(err){
    res.status(401).send('Invalid token')
  }


}


app.listen(PORT,()=>{
    console.log(`Server is running on port ${PORT}`);
})





