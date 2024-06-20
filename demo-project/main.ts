import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import { expressjwt as jwt } from 'express-jwt'
import bodyParser from 'body-parser'
import * as jsonwebtoken from 'jsonwebtoken'
import qs from 'qs'
import { JwtPayload } from 'jsonwebtoken'
import { existsSync } from 'fs'

const app = express()
app.use(bodyParser.json())

const port = 1606

// Get secret used to verify JWT tokens from TOKEN_SECRET environment variable
const tokenSecret = process.env.TOKEN_SECRET ?? 'super-secret-jwt-secret'

// Allow CORS from http://localhost:3001
app.use(
  cors({
    origin: 'http://localhost:3001',
    credentials: true,
  }),
)

// Parse cookies
app.use(cookieParser())

// redirect to login by default
app.get('/', (req, res) => {
  res.redirect('/login.html')
})

// Serve login page
// This also sets a random nonce and state cookie that is used for constructing the openid connect request
app.get('/login.html', (req, res) => {
  const nonce = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15)
  const state = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15)
  res.cookie('nonce', nonce, { maxAge: 900000 })
  res.cookie('state', state, { maxAge: 900000 })
  if (existsSync(`${process.cwd()}/demo-frontend/login.html`)) {
    res.sendFile(`${process.cwd()}/demo-frontend/login.html`)
  } else {
    res.sendFile('/srv/demo-frontend/login.html')
  }
})

// This is a protected endpoint that requires a valid JWT token
app.get('/protected', jwt({ secret: tokenSecret, algorithms: ['HS256'] }), (req, res) => {
  // @ts-expect-error - express-jwt adds auth to request
  const token = req.auth
  // check that token.nonce matches the nonce cookie
  if (token.nonce !== req.cookies.nonce) {
    res.status(401).send('Invalid nonce')
    return
  }
  const name = getNameFromToken(token)
  res.send('Hello from protected route ' + name)
})

// This is a protected endpoint that requires a valid Authorization Code.
app.post('/protected/AuthorizationCode', async (req, res) => {
  const codeRequestBody = {
    code: req.body.auth_code,
    grant_type: 'authorization_code',
    redirect_uri: 'http://localhost:1606/callback.html',
    client_id: 'example-client',
    client_secret: 'insecure_client_secret',
  }
  const response: Response = await fetch('http://localhost:3001/api/v1/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: qs.stringify(codeRequestBody),
  })
  const idToken = (await response.json()).id_token

  const decodedToken = jsonwebtoken.verify(idToken, tokenSecret) as JwtPayload
  if (decodedToken.nonce !== req.cookies.nonce) {
    res.status(401).send('Invalid nonce')
    return
  }
  const name = getNameFromToken(decodedToken)
  res.send('Hello from protected route ' + name)
})

// Serve the rest of the static files
app.use('/', express.static('demo-frontend'))

// Start the server
app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})

// use the token to get the user's web3 name, if not present use the users DID
function getNameFromToken(token) {
  return token.w3n ? `w3n:${token.w3n}` : token.sub
}
