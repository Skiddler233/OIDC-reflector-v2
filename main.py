import os
from flask import Flask, jsonify, session, render_template, abort, url_for, redirect, request
import dotenv
import jwt
from authlib.jose import jwt, JsonWebKey
from authlib.integrations.flask_client import OAuth
import uuid
import requests
import json


# Initialise Flask app
app = Flask(__name__)
dotenv.load_dotenv() # Load .env variables
app.secret_key = os.getenv('APP_SESSION_SECRET') # Secret to hold session open set what you like

# .env variables
CLIENT_ID = os.environ.get("CLIENT_ID") # Provided by OIDC Client
CLIENT_SECRET = os.environ.get("CLIENT_SECRET") # Provided by OIDC Client
REDIRECT_URI = os.environ.get("REDIRECT_URI") # Configured in OIDC Client setup (Callback URL)
TOKEN_ENDPOINT = os.environ.get("TOKEN_ENDPOINT") # Found in "/.well-known/openid-configuration"
DISCOVERY_URL = os.environ.get("DISCOVERY_URL") # {OIDC client URL}/.well-known/openid-configuration

# Configure oauth registration with .env variables
oauth = OAuth(app)
oidc = oauth.register(
    name="oidc",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=DISCOVERY_URL,
    token_endpoint=TOKEN_ENDPOINT,
    client_kwargs={
        'scope' : 'openid profile email org.cilogon.userinfo', # Specify scope for token -> org.cilogon.userinfo
        'response_mode' : 'jwt' # OIDC response JWT
    }
)

RELEVENT_CLAIMS = [
    "sub", "email", "eppn", "eptid",  "family_name", "given_name",
    "idp_name", "isMemberOf", "iss", "jti", "nonce", "auth_time",
    "exp", "acr", "aud", "nbf", "idp", "affilliation", "iat"
]
KNOWN_CLAIMS = [
    "sub", "email", "eppn", "eptid",  "family_name", "given_name",
    "idp_name", "isMemberOf", "iss", "jti", "nonce", "auth_time",
    "exp", "acr", "aud", "nbf", "idp", "affilliation", "iat"
    "eduperson_targeted_id", "aueduperson_shared_token",
    "home_organization", "home_organization_type", "mobile",
    "name","eduperson_affiliation", "eduperson_scoped_affiliation",
    "nickname","organization_name", "idp_entityid", "OIDC_access_token",
    "OIDC_access_token_expires", "cert_subject_dn", "uid"
]

# Home route
@app.route('/')
def index():
    # Contains a button for link to '/login' route
    return render_template('index.html')

# Login route - handles redirect
@app.route('/login')
def login():
    nonce = str(uuid.uuid4())
    session['nonce'] = nonce
    redirect_uri = REDIRECT_URI
    print("doing login route")
    return oidc.authorize_redirect(redirect_uri, nonce=nonce)

# Decoder and validator for ID Token
def decode_id_token(id_token, jwks_uri):
    jwks = requests.get(jwks_uri).json()
    key_set = JsonWebKey.import_key_set(jwks)
    claims = jwt.decode(id_token, key_set)
    claims.validate()
    return dict(claims)

def build_claim_view(token: dict, mode: str) -> dict:
    if mode == "short":
        return {
            k: token[k]
            for k in RELEVENT_CLAIMS
            if k in token
        }
    if mode == "full":
        return dict(token.items())
    if mode == "all":
        all_claims = KNOWN_CLAIMS | token.keys()
        return {
            k: token.get(k, "No Value")
            for k in all_claims
        }
    abort(400)

# Authenticate route - matches the REDIRECT URI - Callback URL
@app.route('/authenticate')
def authenticate():
    
    token = oidc.authorize_access_token()

    nonce = session.pop("nonce", None)
    if not nonce:
        abort(401)

    oidc.parse_id_token(token, nonce=nonce)

    id_token = token["id_token"]
    jwks_uri = oidc.server_metadata["jwks_uri"]

    decoded_token = decode_id_token(id_token, jwks_uri)

    session["decoded_token"] = decoded_token

    return redirect(url_for("results", mode="short"))

@app.route("/results")
def results():
    token = session["decoded_token"]
    if not token:
        abort(401)

    mode = request.args.get("mode", "short")
    claims = build_claim_view(token, mode)
    return render_template(
        "results.html",
        claims=claims,
        mode=mode
    )



@app.route('/unprotected')
def unprotected():
    
    return render_template("results.html", claim_keys=claim_keys, token={})

if __name__ == '__main__':
    app.run(debug=True)