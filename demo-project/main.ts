
import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import { expressjwt as jwt } from 'express-jwt'
import * as path from "path"

const app = express()
const port = 1606

// Get secret used to verify JWT tokens from TOKEN_SECRET environment variable
const tokenSecret = process.env.TOKEN_SECRET ?? 'super-secret-jwt-secret'

// Allow CORS from http://localhost:3001
app.use(cors({
  origin: 'http://localhost:3001',
  credentials: true
}))

// Parse cookies
app.use(cookieParser());

// redirect to login by default
app.get('/', (req, res) => {
  res.redirect('/login.html')
})

// Serve login page
// This also sets a random nonce and state cookie that is used for constructing the openid connect request 
app.get('/login.html', (req, res) => {
  const nonce = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15)
  const state = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15)
  res.cookie('nonce', nonce, { maxAge: 900000 });
  res.cookie('state', state, { maxAge: 900000 });
  res.sendFile('/home/adel/opendid/demo-project/demo-frontend/login.html')
})

// This is a protected endpoint that requires a valid JWT token
app.get('/protected', jwt({ secret: tokenSecret, algorithms: ['HS256'] }), (req, res) => {
  // @ts-ignore - express-jwt adds auth to request
  let token = req.auth;
  // check that token.nonce matches the nonce cookie
  if (token.nonce !== req.cookies.nonce) {
    res.status(401).send('Invalid nonce')
    return
  }
  // use the token to get the user's web3 name, if not present use the users DID
  const name = token.w3n ? `w3n:${token.w3n}` : token.sub
  res.send('Hello from protected route ' + name)
})

// Serve the rest of the static files
app.use('/', express.static('demo-frontend'))

// Start the server
app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
