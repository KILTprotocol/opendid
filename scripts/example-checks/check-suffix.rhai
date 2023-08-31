// This is a simple example of a login policy that allows only users with an email address ending with `kilt.io` to login.

let SUFFIX = "kilt.io";

// ID_TOKEN contains the id_token as to be send to the user from the OIDC provider
let token = parse_id_token(ID_TOKEN);

// We can inspect the token and especially the `pro` sub-object that contains the users claims
if token.pro.Email.ends_with(SUFFIX) {
  // The user is allowed to login
  return true;
}

// The user is not allowed to login
return false;
