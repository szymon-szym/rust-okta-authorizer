use aws_lambda_events::apigw::{
    ApiGatewayCustomAuthorizerRequest,
    ApiGatewayCustomAuthorizerResponse
};

use lambda_runtime::{run, service_fn, Error, LambdaEvent};
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

mod dynamo_service;
mod jwt_service;
mod iam_policy;

#[derive(Serialize, Deserialize)]
pub struct AuthContext {
    text: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct JWTK {
    kid: String,
    kty: String,
    alg: String,
    #[serde(rename = "use")]
    uses: String,
    e: String,
    n: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct JWTKResponse {
    keys: Vec<JWTK>,
}

//stored keys

#[derive(Serialize, Deserialize, Debug)]
pub struct StoredKeys {
    keys: HashMap<String, JWTK>,
}

#[derive(Deserialize, Serialize)]
pub struct Claims {
    aud: String, // Optional. Audience
    exp: usize, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    iat: usize, // Optional. Issued at (as UTC timestamp)
    iss: String, // Optional. Issuer
    uid: String,
    sub: String,      // Optional. Subject (whom token refers to)
    scp: Vec<String>, // Optional. Scopes (permissions)>
}

async fn function_handler(
    current_keys: &StoredKeys,
    event: LambdaEvent<ApiGatewayCustomAuthorizerRequest>,
) -> Result<ApiGatewayCustomAuthorizerResponse<AuthContext>, Error> {

    let token: String  = event.payload.authorization_token.unwrap();

    let token_data: Result<jsonwebtoken::TokenData<Claims>, anyhow::Error> = jwt_service::validate_token(&token, current_keys);

    let response: ApiGatewayCustomAuthorizerResponse<AuthContext> = iam_policy:: prepare_response(token_data)?;

    return Ok(response)
}

#[tokio::main]
async fn main() -> Result<(), Error> {

    let table_name = std::env::var("KEYS_TABLE_NAME").unwrap();
    
    let okta_keys_endpoint = std::env::var("OKTA_KEYS_ENDPOINT").unwrap();

    let dynamo_client = dynamo_service::get_dynamo_client().await;

    println!("getting keys from dynamo");

    let keys_from_dynamo = dynamo_service::get_keys_from_dynamo(&dynamo_client, &table_name).await;

    // if keys are present in dynamo - use them
    // get them from Okta and store in dynamo

    let stored_keys: StoredKeys = match keys_from_dynamo {
        Ok(keys_dynamo) => {
            println!("got keys from dynamo");
            jwtk_response_to_map(keys_dynamo)
        }
        Err(_) => {
            println!("no keys in dynamo - getting them from okta and storing in  dynamo");
            let keys_resp = get_keys_from_okta(okta_keys_endpoint).await.unwrap();
            // ignoring result of putting record to dynamo
            let _ =
                dynamo_service::store_keys_in_dynamo(&dynamo_client, &table_name, &keys_resp).await;
            jwtk_response_to_map(keys_resp)
        }
    };

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        // disable printing the name of the module in every log line.
        .with_target(false)
        // disabling time is handy because CloudWatch will add the ingestion time.
        .without_time()
        .init();

    // run(service_fn(function_handler)).await
    run(service_fn(|event| function_handler(&stored_keys, event))).await
}

fn jwtk_response_to_map(keys_resp: JWTKResponse) -> StoredKeys {
    keys_resp.keys.into_iter().fold(
        StoredKeys {
            keys: HashMap::new(),
        },
        |mut acc, key| {
            acc.keys.insert(key.kid.clone(), key);
            acc
        },
    )
}

async fn get_keys_from_okta(endpoint: String) -> anyhow::Result<JWTKResponse> {
    let result = reqwest::get(endpoint).await?.json::<JWTKResponse>().await?;
    Ok(result)
}
