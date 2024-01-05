const express = require("express");
const bodyParser = require("body-parser");
const Joi = require('joi');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const jwt = require("jsonwebtoken");
const { MongoClient, ServerApiVersion } = require('mongodb');
const mongoose = require("mongoose");

const { Snowflake } = require("@theinternetfolks/snowflake");

let app = express();
app.use(bodyParser.urlencoded({extended:false}));
app.use(bodyParser.json());
// mongoose.connect("mongodb://0.0.0.0:27017/TIFDB", {useNewUrlParser: true});

const uri = "mongodb+srv://admin:<DB_PASSWORD>@cluster0.6deskvl.mongodb.net/TIFDB?retryWrites=true&w=majority";
// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});
async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    await client.close();
  }
}
run().catch(console.dir);

const userSchema = {
    id: String,
    name: String,
    email: String,
    password: String,
    created_at: Date
}

const communitySchema = {
    id: String,
    name: String,
    slug: String,
    owner: [userSchema],
    created_at: Date,
    updated_at: Date
}

const roleSchema = {
    id: String,
    name: String,
    created_at: Date,
    updated_at: Date
}

const memberSchema = {
    id: String,
    community: [communitySchema],
    user: [userSchema],
    role: [roleSchema],
    created_at: Date
}

const User = mongoose.model("user", userSchema);
const Community = mongoose.model("community", communitySchema);
const Role = mongoose.model("Role", roleSchema);
const Member = mongoose.model("Member", memberSchema);

app.post("/v1/role", async (req,res)=>{
    try{
        const schema = Joi.object({
            name: Joi.string().min(2).max(64).required()
          });

        const { error } = schema.validate(req.body);

        if(error)
        {
            return res.status(400).json({
                status: false,
                errors: [{
                  param: error.details[0].context.key,
                  message: "Name should be at least 2 characters.",
                  code: 'INVALID_INPUT'
                }]
              });
        }

        const newRole = new Role({
            id: Snowflake.generate(),
            name: req.body.name,
            created_at: Date.now(),
            updated_at: Date.now(),
        });
        newRole.save();

        return res.status(200).json({
            status: true,
            content: {
              data: {
                id: newRole.id,
                name: newRole.name,
                created_at: newRole.created_at,
                updated_at: newRole.updated_at,
              }
            }
          });

    }catch(err){
        console.error(err);
        return res.status(500).json({ status: false, error: 'Internal server error' });
    }
})

app.get("/v1/role", async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1; 
        const perPage = 10;

        const totalRoles = await Role.countDocuments();
        const totalPages = Math.ceil(totalRoles / perPage); 

        const roles = await Role.find()
            .skip((page - 1) * perPage) 
            .limit(perPage); 

        const formattedRoles = roles.map(role => ({
            id: role.id,
            name: role.name,
            created_at: role.created_at,
            updated_at: role.updated_at
        }));

        return res.status(200).json({
            status: true,
            content: {
                meta: {
                    total: totalRoles,
                    pages: totalPages,
                    page: page
                },
                data: formattedRoles
            }
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ status: false, error: 'Internal server error' });
    }
});

app.post("/v1/auth/signup", async (req,res)=>{
    try{
        const { name, email, password } = req.body;

        if (!name || name.length < 2) {
            return res.status(400).json({
              status: false,
              errors: [{
                param: "name",
                message: "Name should be at least 2 characters.",
                code: 'INVALID_INPUT'
              }]
            });
          }

          if (!password || password.length < 6){
            return res.status(400).json({
                status: false,
                errors: [{
                  param: "password",
                  message: "Password should be at least 6 characters.",
                  code: 'INVALID_INPUT'
                }]
              });
          }

          else
          {
            const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{6,}$/;
            if (!req.body.password.match(passwordRegex)) {
            return res.status(400).json({
                status: false,
                errors: [{
                param: 'password',
                message: 'Password should be at least 6 characters long and contain at least one lowercase letter, one uppercase letter, and one digit',
                code: 'WEAK_PASSWORD'
                }]
            });
            }
          }          

            const existingUser = await User.findOne({ email: req.body.email });
            if (existingUser) {
            return res.status(400).json({
                status: false,
                errors: [{
                param: 'email',
                message: 'User with this email address already exists.',
                code: 'RESOURCE_EXISTS'
                }]
            });
            }

             const hashedPassword = await bcrypt.hash(req.body.password, 10);

            const newUser = await User.create({
                id: Snowflake.generate(),
                name: req.body.name,
                email: req.body.email,
                password: hashedPassword,
                created_at: Date.now(),
            });
            newUser.save();

            const accessToken = jwt.sign({ userId: newUser.id }, 'mySecret', { expiresIn: '1h' });

            return res.status(200).json({
                status: true,
                content: {
                    data: {
                        id: newUser.id,
                        name: newUser.name,
                        email: newUser.email,
                        created_at: newUser.created_at
                    },
                    meta: {
                        access_token: accessToken
                    }
                }
            });
    }catch(error){
        console.error(error);
        return res.status(500).json({ status: false, error: 'Internal server error' });
    }
})

app.post("/v1/auth/signin", async (req, res) =>{
    try{
        const {email, password} = req.body;

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!req.body.email.match(emailRegex)){
            return res.status(400).json({
                status: false,
                errors: [{
                param: 'email',
                message: 'Please provide a valid email address.',
                code: 'INVALID_INPUT'
                }]
            });
        }

        const existingUser = await User.findOne({ email: req.body.email });
        if(existingUser)
        {
            const passwordMatch = await bcrypt.compare(password, existingUser.password);
            if(!passwordMatch)
            {
                return res.status(400).json({
                    status: false,
                    errors: [{
                    param: 'password',
                    message: 'The credentials you provided are invalid.',
                    code: 'INVALID_CREDENTIALS'
                    }]
                });
            }

            else
            {
                const accessToken = jwt.sign({ userId: existingUser.id }, 'mySecret', { expiresIn: '1h' });

                return res.status(200).json({
                    status: true,
                    content: {
                        data: {
                            id: existingUser.id,
                            name: existingUser.name,
                            email: existingUser.email,
                            created_at: existingUser.created_at
                        },
                        meta: {
                            access_token: accessToken
                        }
                    }
                });
            }
        }

        else
        {
            return res.status(400).json({
                status: false,
                errors: [{
                param: 'password',
                message: 'The credentials you provided are invalid.',
                code: 'INVALID_CREDENTIALS'
                }]
            });
        }

    }catch(error){
        console.error(error);
        return res.status(500).json({ status: false, error: 'Internal server error' });
    }
})


app.get("/v1/auth/me", async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(400).json({
                message: "You need to sign in to proceed.",
                code: "NOT_SIGNEDIN"
            });
        }

        const token = authHeader.split(' ')[1];

        jwt.verify(token, 'mySecret', async (err, decodedToken) => {
            if (err) {
                return res.status(400).json({
                    message: "You need to sign in to proceed.",
                    code: "NOT_SIGNEDIN"
                });
            }

            const userId = decodedToken.userId;

            try {
                const user = await User.findOne({id: userId});
                
                if (!user) {
                    return res.status(400).json({
                        message: "You need to sign in to proceed.",
                        code: "NOT_SIGNEDIN"
                    });
                }

                return res.status(200).json({
                    status: true,
                    content: {
                        data: {
                            id: user.id,
                            name: user.name,
                            email: user.email,
                            created_at: user.created_at
                        }
                    }
                });
            } catch (error) {
                console.error("Error finding user:", error);
                return res.status(500).json({ status: false, error: 'Internal server error' });
            }
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ status: false, error: 'Internal server error' });
    }
});


function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization']; 

    const token = authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Token not provided' });
    }

    jwt.verify(token, 'mySecret', async (err, decoded) => {
        if (err) {
            console.log(err);
            return res.status(403).json({ message: 'Failed to authenticate token' });
        }
        req.decoded = decoded;
        next();
    });
}

app.post("/v1/community", verifyToken, async (req, res) => {
    try {
        const { name } = req.body;
        const slug = name.toLowerCase().replace(/\s+/g, '-'); 

        if (!name || name.length < 2) {
            return res.status(400).json({
              status: false,
              errors: [{
                param: "name",
                message: "Name should be at least 2 characters.",
                code: 'INVALID_INPUT'
              }]
            });
          }

        const userId = req.decoded.userId; 
        let existingUser = await User.findOne({id: userId});
        console.log("Existing User: ",existingUser);

        const newCommunity = await new Community({
            id: Snowflake.generate(),
            name: name,
            slug: slug,
            owner: [existingUser],
            created_at: new Date(),
            updated_at: new Date()
        });
        newCommunity.save();

        let existingRole = await Role.findOne({name: "Community Admin"});

        const newMember = await new Member({
            id: Snowflake.generate(),
            community: [newCommunity],
            user: [existingUser],
            role: [existingRole], 
            created_at: new Date()
        });
        newMember.save();

        return res.status(200).json({
            status: true,
            content: {
                data: {
                    id: newCommunity.id,
                    name: newCommunity.name,
                    slug: newCommunity.slug,
                    owner: newCommunity.owner.id,
                    created_at: newCommunity.created_at,
                    updated_at: newCommunity.updated_at
                }
            }
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ status: false, error: 'Internal server error' });
    }
});

app.get("/v1/community", async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1; 
        const pageSize = 10; 

        const totalCount = await Community.countDocuments();
        const totalPages = Math.ceil(totalCount / pageSize);

        const communities = await Community.find()
            .skip((page - 1) * pageSize)
            .limit(pageSize)
         
        let formattedCommunities = await Promise.all(communities.map(async community => {
                
                return {
                    id: community.id,
                    name: community.name,
                    slug: community.slug,
                    owner: {
                        id: community.owner[0].id,
                        name: community.owner[0].name
                    },
                    created_at: community.created_at,
                    updated_at: community.updated_at
                };
            }));

        return res.status(200).json({
            status: true,
            content: {
                meta: {
                    total: totalCount,
                    pages: totalPages,
                    page: page
                },
                data: formattedCommunities
            }
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ status: false, error: 'Internal server error' });
    }
});


app.get("/v1/community/:id/members", async (req, res) => {
    try {
        const { id } = req.params;
        console.log("ID: ", id);
        const page = parseInt(req.query.page) || 1;
        const limit = 10;

        const community = await Community.findOne({id: id});

const totalMembers = await Member.countDocuments({ community: community });

const members = await Member.find({ community: community })
    .skip((page - 1) * limit)
    .limit(limit)
    .exec();

const totalPages = Math.ceil(totalMembers / limit);
const pageSize = 10; 

const formattedMembers = members.map(member => ({
    id: member.id,
    community: member.community[0].id,
    user: {
        id: member.user[0].id,
        name: member.user[0].name
    },
    role: {
        id: member.role[0].id,
        name: member.role[0].name
    },
    created_at: member.created_at
}));


return res.status(200).json({
    status: true,
    content: {
        meta: {
            total: totalPages,
            pages: totalPages,
            page: page
        },
        data: [formattedMembers]
    }
});

    } catch (error) {
        console.error(error);
        return res.status(500).json({ status: false, error: 'Internal server error' });
    }
});

app.get("/v1/community/me/owner", verifyToken, async (req, res) => {
    try {
      const page = parseInt(req.query.page) || 1; 
      const pageSize = 10; 
  
      const userId = req.decoded.userId; 
  
      const totalCount = await Community.countDocuments({ 'owner.id': userId });
      const totalPages = Math.ceil(totalCount / pageSize);
  
      const communities = await Community.find({ 'owner.id': userId })
        .skip((page - 1) * pageSize)
        .limit(pageSize);
  
      let formattedCommunities = await Promise.all(
        communities.map(async (community) => {
          return {
            id: community.id,
            name: community.name,
            slug: community.slug,
            owner: community.owner[0].id,
            created_at: community.created_at,
            updated_at: community.updated_at,
          };
        })
      );
  
      return res.status(200).json({
        status: true,
        content: {
          meta: {
            total: totalCount,
            pages: totalPages,
            page: page,
          },
          data: formattedCommunities,
        },
      });
    } catch (error) {
      console.error(error);
      return res.status(500).json({ status: false, error: 'Internal server error' });
    }
  });
  
app.get("/v1/community/me/member", verifyToken, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1; 
      const pageSize = 10; 
  
      const userId = req.decoded.userId; 
  
      const totalCount = await Community.countDocuments({ 'owner.id': userId });
      const totalPages = Math.ceil(totalCount / pageSize);
  
      const members = await Member.find({ 'user[0].id': userId })
        .skip((page - 1) * pageSize)
        .limit(pageSize);
  
      let formattedCommunities = await Promise.all(
        members.map(async (member) => {
          return {
            id: member.community[0].id,
            name: member.community[0].name,
            slug: member.community[0].slug,
            owner: {
                id: member.owner[0].id,
                name: member.owner[0].name,
            },
            created_at: member.community[0].created_at,
            updated_at: member.community[0].updated_at,
          };
        })
      );
  
      return res.status(200).json({
        status: true,
        content: {
          meta: {
            total: totalCount,
            pages: totalPages,
            page: page,
          },
          data: formattedCommunities,
        },
      });
    } catch (error) {
      console.error(error);
      return res.status(500).json({ status: false, error: 'Internal server error' });
    }
  });
  
  async function checkUserRole(userId, communityId)
  {
    console.log(userId, communityId);
    const reqiredCommunity = await Community.findOne({id: communityId});

    console.log(reqiredCommunity);

    if(reqiredCommunity.owner[0].id === userId)
    return 'Community Admin';

    return 'NOT ADMIN';
  }

app.post("/v1/member", verifyToken, async (req, res) => {
    try {
      const { community, user, role } = req.body;
  
      const allowedRole = await checkUserRole(req.decoded.userId, community);
      console.log("ALLOWED: ", allowedRole);
      if (allowedRole !== 'Community Admin') {
        return res.status(403).json({
          status: false,
          error: 'NOT_ALLOWED_ACCESS',
          message: 'Only Community Admin can add a user.',
        });
      }

      let requiredCommunity = await Community.findOne({id: community});
      if(!requiredCommunity)
      {
        return res.status(403).json({
            param: "community",
            message: 'community not found.',
            error: 'RESOURCE_NOT_FOUND',
          });
      }
      let requiredUser = await User.findOne({id: user});
      if(!requiredUser)
      {
        return res.status(403).json({
            param: "user",
            message: 'User not found.',
            error: 'RESOURCE_NOT_FOUND',
          });
      }
      let requiredRole = await Role.findOne({id: role});
      if(!requiredRole)
      {
        return res.status(403).json({
            param: "role",
            message: 'Role not found.',
            error: 'RESOURCE_NOT_FOUND',
          });
      }
  
      const newMember = new Member({
        id: Snowflake.generate(),
        community: requiredCommunity,
        user: requiredUser,
        role: requiredRole,
        created_at: new Date(),
      });
      await newMember.save();
  
      return res.status(200).json({
        status: true,
        content: {
          data: {
            id: newMember.id,
            community: newMember.community[0].id,
            user: newMember.user[0].id,
            role: newMember.role[0].id,
            created_at: newMember.created_at,
          },
        },
      });
    } catch (error) {
      console.error(error);
      return res.status(500).json({ status: false, error: 'Internal server error' });
    }
  });
  

async function checkUserPermissionToDelete(userId, memberId) {
    try {
      const userRole = await getUserRole(userId); 
      const memberRole = await getMemberRole(memberId); 
  
      if (
        userRole === 'Community_Admin' || userRole === 'Community_Moderator'
      ) {
        return true; 
      } else {
        throw new Error('NOT_ALLOWED_ACCESS'); 
      }
    } catch (error) {
      throw new Error('Error checking user permission to delete');
    }
  }
  
  app.delete('/v1/member/:id', async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id; 
  
    try {
      const hasPermission = await checkUserPermissionToDelete(userId, id);
      if (hasPermission) {
        const response = await axios.delete(`http://localhost:3000/v1/member/${id}`, {
          headers: {
            Authorization: `Bearer ${req.headers.authorization}`,
          },
        });
        
        res.status(200).json({ status: true });
      } else {
        res.status(403).json({ error: 'NOT_ALLOWED_ACCESS' });
      }
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
  
  async function getUserRole(userId) {
    let requiredUser = await User.findOne({id: userId});
    let requiredMember = await Member.findOne({user: requiredUser})

    if(requiredMember.role[0].name === 'Community_Admin')
    return 'Admin';
  }
  
  async function getMemberRole(memberId) {
    let requiredUser = await User.findOne({id: userId});
    let requiredMember = await Member.findOne({user: requiredUser})

    if(requiredMember.role[0].name === 'Community_Member')
    return 'Member';
  }


app.listen(3000, (req,res)=>{console.log("PORT@3000");})