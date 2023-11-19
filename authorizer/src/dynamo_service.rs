use anyhow::{anyhow, Context};

use super::JWTKResponse;

pub async fn get_dynamo_client() -> aws_sdk_dynamodb::Client {
    let region_provider =
        aws_config::meta::region::RegionProviderChain::default_provider().or_else("us-east-1");

    let config = aws_config::from_env().region(region_provider).load().await;

    return aws_sdk_dynamodb::Client::new(&config);
}

pub(crate) async fn get_keys_from_dynamo(
    dynamo_client: &aws_sdk_dynamodb::Client,
    table_name: &String,
) -> anyhow::Result<JWTKResponse> {
    let keys_results = dynamo_client
        .get_item()
        .table_name(table_name)
        .key(
            "PK",
            aws_sdk_dynamodb::types::AttributeValue::S("#KEYS".to_string()),
        )
        .send()
        .await?;

    let keys_resp = keys_results.item.context("missing keys in Dynamo")?;

    let keys_json = keys_resp
        .get("keys")
        .context("missing keys attribute")?
        .as_s()
        .map_err(|_| anyhow!("Keys are not a string"))?;

    return Ok(serde_json::from_str(&keys_json)?);
}

pub(crate) async fn store_keys_in_dynamo(
    dynamo_client: &aws_sdk_dynamodb::Client,
    table_name: &String,
    keys: &JWTKResponse,
) -> anyhow::Result<()> {
    let keys_json = serde_json::to_string(&keys)?;

    dynamo_client
        .put_item()
        .table_name(table_name)
        .item(
            "PK",
            aws_sdk_dynamodb::types::AttributeValue::S("#KEYS".to_string()),
        )
        .item(
            "keys",
            aws_sdk_dynamodb::types::AttributeValue::S(keys_json),
        )
        .send()
        .await?;

    Ok(())
}
