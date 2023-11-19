use aws_lambda_events::apigw::{
    ApiGatewayCustomAuthorizerPolicy, ApiGatewayCustomAuthorizerResponse, IamPolicyStatement,
};

use crate::{AuthContext, Claims};

pub fn prepare_response(
    validated_token: anyhow::Result<jsonwebtoken::TokenData<Claims>>,
) -> anyhow::Result<ApiGatewayCustomAuthorizerResponse<AuthContext>> {
    let policy = match validated_token {
        Ok(token_data) => {
            let path_to_allow = format!(
                "arn:aws:execute-api:us-east-1:765444088049:qma7pp9zmf/Prod/GET/hello/{user_id}",
                user_id = token_data.claims.uid
            );

            let statement = vec![IamPolicyStatement {
                effect: Some("Allow".to_string()),
                action: vec!["execute-api:Invoke".to_string()],
                resource: vec![path_to_allow],
            }];

            ApiGatewayCustomAuthorizerPolicy {
                version: Some("2012-10-17".to_string()),
                statement,
            }
        }
        Err(e) => {
            println!("token validation failed with error: {:?}", e);

            let path_to_deny =
                format!("arn:aws:execute-api:us-east-1:765444088049:qma7pp9zmf/Prod/GET/hello/*",);

            let statement = vec![IamPolicyStatement {
                effect: Some("Deny".to_string()),
                action: vec!["execute-api:Invoke".to_string()],
                resource: vec![path_to_deny],
            }];

            ApiGatewayCustomAuthorizerPolicy {
                version: Some("2012-10-17".to_string()),
                statement,
            }
        }
    };
    // Prepare the response
    let resp = ApiGatewayCustomAuthorizerResponse {
        principal_id: Some("12345abc".to_string()),
        policy_document: policy,
        context: AuthContext {
            text: "dummy context".to_string(),
        },
        usage_identifier_key: None,
    };
    return Ok(resp);
}
