use crate::{Claims, StoredKeys, JWTK};

pub fn validate_token(
    token: &String,
    current_keys: &StoredKeys,
) -> anyhow::Result<jsonwebtoken::TokenData<Claims>> {

    let token_header: jsonwebtoken::Header = jsonwebtoken::decode_header(&token)?;
    
    let kid: String = token_header.kid.unwrap();
    
    let public_key_to_use: &JWTK = current_keys.keys.get(&kid).unwrap();
    
    let decoding_key: jsonwebtoken::DecodingKey =
        jsonwebtoken::DecodingKey::from_rsa_components(&public_key_to_use.n, &public_key_to_use.e)?;
    
    let expected_aud: String = "api://default".to_string();
    
    let mut validation: jsonwebtoken::Validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    
    validation.set_audience(&[expected_aud]);
    
    let token_data: jsonwebtoken::TokenData<Claims> = jsonwebtoken::decode::<Claims>(&token, &decoding_key, &validation)?;
    
    return Ok(token_data);
}
