
import express from 'express'
import cors from 'cors'
import { expressjwt as jwt } from 'express-jwt'

const app = express()
const port = 1606
const tokenSecret = '0xcaa191cbdf3422d3a6ebf970a090aaeacc01ba50b3602dbcb452e27fe06b1d50c55153cd10f5a2fdd4c0ebfaeecdb8c0584671a77336c54c286e90a49e7a2d7d'

// allow CORS from http://localhost:3001
app.use(cors({
    origin: 'http://localhost:3001',
    credentials: true
}))

// use JWT middleware
app.get('/protected', jwt({ secret: tokenSecret, algorithms: ['HS256'] }), (req, res) => {
    // @ts-ignore - express-jwt adds auth to request
    let token = req.auth;
    console.log(token)
    res.send('Hello from protected route '+token.sub)
})

// serve static files from directory demo-frontend
app.use(express.static('demo-frontend'))

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})