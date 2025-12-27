const express=require("express")
const { Pool }=require("pg")
const cookieParser=require("cookie-parser")
const path=require("path")
const app=express();
const bcrypt=require("bcryptjs")
const db = new Pool({
  host: "localhost",
  user: "bekam",
  password: "pass",
  database: "derash",
  port: 5432,
});

const crypto=require("crypto")
app.use(express.urlencoded({
  extended:true
}))
app.use(express.json())

app.use(express.static(path.join(__dirname,"views")))

app.use(express.static(__dirname))
app.use("/",express.static(path.join(__dirname,"views/index.html")))
app.use(cookieParser("mysecretkey"))
function auth(req,res,next){
  const session_id=req.signedCookies.city_admins_session_id || req.headers["x-session-id"];
  const type=req.signedCookies.type;
  
  if (!session_id){
    console.log("no session id")
    return res.status(401).json({ message: "no session id" });
  }
  if (!type){
    return res.status(401).json({ message: "no account type" });
  }
  
  db.query("select * from sessions where session_id = $1",[session_id],(err,results)=>{
    if(err){
      res.json({message:"Internal SQL error"})
    }
    if(results.rows.length===0){
    return res.json("Invalid session")
    }
    req.user_id=results.rows[0].user_id
    req.type=type
    next();
  })
}

app.post("/signUp",async(req,res)=>{
  if(!req.body){
    res.json({message:"Error no data"})
    return;
  }
  const profileColors = [
  "#0388D2", "#00579B", "#0098A7", "#00897B", "#004D40",
  "#68A039", "#EF6C00", "#F6511E", "#C1175C", "#AA47BD",
  "#7B1FA2", "#512DA7", "#455A65",
  "#D32F2F", "#388E3C", "#303F9F", "#FBC02D", "#5D4037"
];
  const randomColor=profileColors[Math.floor(Math.random()*profileColors.length)]
  const {fname,lname,password,phone_number,location,email}=req.body
  const name=`${fname} ${lname}`
  const safePassword=await bcrypt.hash(password,10)
  db.query("select * from users where email = $1;",[email],(err,results)=>{
    if(err){
      res.json({message:"Internal server error"})
      console.log(err)
      return;
    }
    if(results.rows.length !== 0){
      res.json({message:"user exist"})
      return;
    }
    
    db.query("Insert into users (name,email,password,phone_number,location,color) values ($1,$2,$3,$4,$5,$6) RETURNING id;",[name,email,safePassword,phone_number,location,randomColor],(error,result)=>{
      if(error){
      res.json({message:"Internal server error"})
      console.log(error)
      return;
    }
    const user_id=result.rows[0].id
    const session_id=crypto.randomBytes(16).toString("hex")
    db.query("insert into sessions (user_id,session_id) values($1,$2)",[user_id,session_id],(err,data)=>{
     if(err){
      res.json({message:"Internal server error"})
      console.log(err)
      return;
    } 
    res.cookie("type", "personal", {
      httpOnly: true,
      signed: true,
      maxAge: 10 * 365 * 24 * 60 * 60 * 1000
    });
    res.cookie("city_admins_session_id", session_id, {
      httpOnly: true,
      signed: true,
      maxAge: 10 * 365 * 24 * 60 * 60 * 1000
    });
    res.json({message:"succesfull"})
    })
    
    })
  })
})

app.post("/signIn",(req,res)=>{
  if(!req.body){
    res.json({message:"Error no data"})
    return;
  }
  const {password,email}=req.body
  db.query("select * from users where email = $1;",[email],async(err,results)=>{
    if(err){
      res.json({message:"Internal server error"})
      console.log(err)
      return;
    }  
    
    if(results.rows.length === 0 ){
      return res.json({message:"user don't exist"});
    }
    const isMached=await bcrypt.compare(password,results.rows[0].password)
    if(!isMached){
    return res.json({message:"password don't match"})
    }
    if(isMached){
      const session_id=crypto.randomBytes(16).toString("hex")
      db.query("insert into sessions(session_id,user_id) values ($1,$2);",[session_id,results.rows[0].id],(err,result)=>{
    if(err){
      res.json({message:"Internal server error"})
      console.log(err)
      return;
    }  
    res.cookie("type", "personal", {
      httpOnly: true,
      signed: true,
      maxAge: 10 * 365 * 24 * 60 * 60 * 1000
    });
    res.cookie("city_admins_session_id",session_id,{
      signed:true,
      httpOnly:true,
      maxAge: 10 * 365 * 24 * 60 * 60 * 1000
    })
    res.json(
      {message:"succesfull"})
      })
    }
  })
}) 

app.post("/orgSignUp",async(req,res)=>{
  if(!req.body){
    res.json({message:"Error no data"})
    return;
  }
  const profileColors = [
  "#0388D2", "#00579B", "#0098A7", "#00897B", "#004D40",
  "#68A039", "#EF6C00", "#F6511E", "#C1175C", "#AA47BD",
  "#7B1FA2", "#512DA7", "#455A65",
  "#D32F2F", "#388E3C", "#303F9F", "#FBC02D", "#5D4037"
];
  const randomColor=profileColors[Math.floor(Math.random()*profileColors.length)]
  const {orgName,password,phone_number,email}=req.body
  const safePassword=await bcrypt.hash(password,10)
  console.log("organizations")
  db.query("select * from organizations where org_email= $1;",[email],(err,results)=>{
    if(err){
      res.json({message:"Internal server error"})
      console.log(err)
      return;
    }
    if(results.rows.length !== 0){
      res.json({message:"organization exist"})
      return;
    }
    
    db.query("Insert into organizations (name,org_email,password,phone_number,color) values ($1,$2,$3,$4,$5) RETURNING id;",[orgName,email,safePassword,phone_number,randomColor],(error,result)=>{
      if(error){
      res.json({message:"Internal server error"})
      console.log(error)
      return;
    }
    const organization_id=result.rows[0].id
    const session_id=crypto.randomBytes(16).toString("hex")
    db.query("insert into sessions (user_id,session_id) values($1,$2)",[organization_id,session_id],(err,data)=>{
    if(err){
      res.json({message:"Internal server error"})
      console.log(err)
      return;
    } 
    res.cookie("type", "organizational", {
      httpOnly: true,
      signed: true,
      maxAge: 10 * 365 * 24 * 60 * 60 * 1000
    });
    res.cookie("city_admins_session_id", session_id, {
      httpOnly: true,
      signed: true,
      maxAge: 10 * 365 * 24 * 60 * 60 * 1000
    });
    res.json(
      {message:"succesfull"})
    })
    
    })
  })
})

app.post("/orgSignIn",(req,res)=>{
  if(!req.body){
    res.json({message:"Error no data"})
    return;
  }
  const {password,email}=req.body
  db.query("select * from organizations where org_email = $1;",[email],async(err,results)=>{
    if(err){
      res.json({message:"Internal server error"})
      console.log(err)
      return;
    }  
    
    if(results.rows.length === 0 ){
      return res.json({message:"user don't exist"});
    }
    const isMached=await bcrypt.compare(password,results.rows[0].password)
    if(!isMached){
    return res.json({message:"password don't match"})
    }
    if(isMached){
      const session_id=crypto.randomBytes(16).toString("hex")
      db.query("insert into sessions(session_id,user_id) values ($1,$2);",[session_id,results.rows[0].id],(err,result)=>{
    if(err){
      res.json({message:"Internal server error"})
      console.log(err)
      return;
    }  
    res.cookie("type", "organizational", {
      httpOnly: true,
      signed: true,
      maxAge: 10 * 365 * 24 * 60 * 60 * 1000
    });
    res.cookie("city_admins_session_id",session_id,{
      signed:true,
      httpOnly:true,
      maxAge: 10 * 365 * 24 * 60 * 60 * 1000
    })
    res.json(
      {message:"succesfull"})
      })
    }
  })
}) 

app.post("/userInfo",auth,(req,res)=>{
  const user_id=req.user_id
  const type=req.type
  if(type==="personal"){
  db.query("select * from users where id = $1",[user_id],(err,results)=>{
    if(err){
      res.json({message:"Internal server error"})
      console.log(err)
      return;
    }  
    if(results.rows.length === 0 ){
      return res.json({message:"user don't exist"});
    }
        const {name,email,color}=results.rows[0]
    const info={name,email,color,type}
    res.json({message:info})
  })
  }
  else if(type==="organizational"){
  db.query("select * from organizations where id = $1",[user_id],(err,results)=>{
    if(err){
      res.json({message:"Internal server error"})
      console.log(err)
      return;
    }  
    if(results.rows.length === 0 ){
      return res.json({message:"user don't exist"});
    }
    const {name,org_email:email,color}=results.rows[0]
    const info={name,email,color,type}
    res.json({message:info})
  })
    
  }
})

app.get("/signout", async (req, res) => {
  const session_id = req.signedCookies.city_admins_session_id || req.headers["x-session-id"];
  if (!session_id) return res.status(401).json({ message: "no session id" });
  try {
    await db.query("DELETE FROM sessions WHERE session_id=$1;", [session_id]);
    res.clearCookie("city_admins_session_id", { httpOnly: true, signed: true, path: "/" });
    res.clearCookie("type", { httpOnly: true, signed: true, path: "/" });
    res.set("Cache-Control", "no-store");
    res.redirect("/");} catch (err) {
    sqlError(err, res);
  }
});

app.post("/getOrganizations",(req,res)=>{
  db.query("select * from organizations;",(err,results)=>{
  if(err){
      res.json({message:"Internal server error"})
      console.log(err)
      return;
    }    
    const safeRows = results.rows.map(({ name, color,org_email,...rest}) => {
      return {name,color,org_email}
      
    });
   res.json(safeRows);
  })
})

app.post("/sentMessage",auth,(req,res)=>{
  const user_id=req.user_id
  const org_type=req.type
  const {title,description,choosenOrg}=req.body
  console.log(JSON.stringify({title,description,choosenOrg}))
  if(title && description && choosenOrg){
    db.query("select * from organizations where org_email = $1;",[choosenOrg],(err,results)=>{
      if(err){
      res.json({message:"Internal server error"})
      console.log(err)
      return;
    }     
      if(results.rows.length !==0){
      const org_id=results.rows[0].id
      db.query('insert into messages(org_id,title,message,sender_id,type) values($1,$2,$3,$4,$5);',[org_id,title,description,req.user_id,req.type],(error,result)=>{
      if(error){
      res.json({message:"Internal server error"})
      console.log(err)
      return;
    }   
    res.json({message:"succesfull"})
      })  
      }
    })
  }
})


app.post("/getAllMessages",auth,(req,res)=>{
  const org_id=req.user_id
  const page=req.body.page
  console.log(page)
  let where=page=="home" ? "sender_id" : "org_id"
  let whereTo= page=="home" ? "org_id" : "sender_id"
  db.query(`select * from messages where ${where} = $1 order by id desc;`,[org_id],async(err,results)=>{
    if(err){
      res.json({message:"Internal server error"})
      console.log(err)
      return;
    }  
    const users = await db.query('select * from users;')

   const organs=await db.query('select * from organizations;')
     
  const fullMsInfo=[]
  results.rows.forEach(message=>{
    console.log(message[whereTo],whereTo,"hi bekam")
    if(message.type =="personal" && page ==="manage"){
    users.rows.forEach(user=>{
      if(Number(user.id)===Number(message.sender_id)){
    const {id:userId,password,...restU}=user    
    const {org_id,sender_id,...restM}=message
    fullMsInfo.push({...restU,...restM})
      }
    })
    }
    else if(message.type =="personal" && page ==="home"){
    organs.rows.forEach(organ=>{
      if(Number(organ.id)===Number(message[whereTo])){
    const {id:userId,password,...restO}=organ    
    const {org_id,sender_id,...restM}=message
    fullMsInfo.push({...restO,...restM})
      }
    })  
    }
    else if(message.type =="organizational"){
    organs.rows.forEach(organ=>{
      if(Number(organ.id)===Number(message[whereTo])){
    const {id:userId,password,...restO}=organ    
    const {org_id,sender_id,...restM}=message
    fullMsInfo.push({...restO,...restM})
      }
    })
    }
  })
  
  console.log(JSON.stringify(fullMsInfo))
  res.json(fullMsInfo)
  })
})


app.post("/sendReply",auth,(req,res)=>{
  const {msg_id,toRep,repDescription}=req.body
  db.query("insert into reply(msg_id,replieyer_id,replay_msg,replieyer_type) values($1,$2,$3,$4)",[msg_id,req.user_id,repDescription,req.type],(err,results)=>{
    if(err){
      res.json({message:"Internal server error"})
      console.log(err)
      return;
    }  
    db.query("delete from reply_drafts where msg_id=$1;",[msg_id])
    res.json({message:"succesfull"})
  })
})

app.post("/getAllDrafts",auth,(req,res)=>{
  const org_id=req.user_id
  db.query("select * from reply_drafts where org_id=$1",[org_id],(err,results)=>{
    if(err){
      res.json({message:"Internal server error"})
      console.log(err)
      return;
    }  
    res.json(results.rows)
  })
})

app.post("/sendDraft",auth,(req,res)=>{
  const {msg_id,toRep,repDescription,fromRep}=req.body
  db.query("delete from reply_drafts where msg_id=$1;",[msg_id])
  db.query("insert into reply_drafts(msg_id,org_id,fromRep,toRep,message) values($1,$2,$3,$4,$5)",[msg_id,req.user_id,fromRep,toRep,repDescription],(err,results)=>{
    if(err){
      res.json({message:"Internal server error"})
      console.log(err)
      return;
    }  
    res.json({message:"succesfull"})
  })
})

app.post("/checkAsRead",(req,res)=>{
  const msg_id=Number(req.body.msg_serial)
  const read="true"
  console.log(msg_id)
  db.query('update messages set read=$1 where id=$2 ',[read,msg_id],(err,results)=>{
   if(err){
      res.json({message:"Internal server error"})
      console.log(err)
      return;
    }   
    res.json({message:"succesfull"})
  })
})

app.post("/checkAsArchived",(req,res)=>{
  const msg_id=Number(req.body.msg_serial)
  const archived=req.body.archive
  console.log(msg_id)
  db.query('update messages set archived=$1 where id=$2 ',[archived,msg_id],(err,results)=>{
   if(err){
      res.json({message:"Internal server error"})
      console.log(err)
      return;
    }   
    res.json({message:"succesfull"})
  })
})

app.listen(3000,()=>{
  console.log("server running on http://localhost:3000")
})