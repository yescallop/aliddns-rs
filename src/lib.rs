use anyhow::{anyhow, Context, Result};
use base64::prelude::*;
use chrono::{SecondsFormat, Utc};
use curl::easy::Easy;
use hmac_sha1::hmac_sha1;
use serde::Deserialize;
use std::{net::IpAddr, time::Duration};
use urlencoding::encode as urlencode;

const API_VERSION: &str = "2015-01-09";
const SIGNATURE_METHOD: &str = "HMAC-SHA1";
const SIGNATURE_VERSION: &str = "1.0";
const ACTION: &str = "UpdateDomainRecord";
const API_GLOBAL_V4: &str = "http://api-ipv4.ip.sb/ip";
const CURL_TIMEOUT: Duration = Duration::from_secs(5);

pub mod ifaddrs;
mod sockaddr;

#[derive(Deserialize)]
pub struct Config {
    pub interval_secs: u64,
    pub access_key_id: String,
    pub access_key_secret: String,
    pub record_id_v4: Option<u64>,
    pub record_id_v6: Option<u64>,
    #[serde(default)]
    pub global_v4: bool,
    #[serde(default)]
    pub static_v6: bool,
    pub rr: String,
}

pub fn update_record(config: &Config, value: IpAddr, id: u64) -> Result<()> {
    let now = Utc::now();
    let signature_nonce = now.timestamp_millis();
    let timestamp = now.to_rfc3339_opts(SecondsFormat::Secs, true);
    let r#type = match value {
        IpAddr::V4(_) => "A",
        IpAddr::V6(_) => "AAAA",
    };

    let mut query = format!(
        "AccessKeyId={}&Action={}&Format=JSON&RR={}&RecordId={}&SignatureMethod={}&SignatureNonce={}&SignatureVersion={}&Timestamp={}&Type={}&Value={}&Version={}",
        config.access_key_id,
        ACTION,
        urlencode(&config.rr),
        id,
        SIGNATURE_METHOD,
        signature_nonce,
        SIGNATURE_VERSION,
        urlencode(&timestamp),
        r#type,
        urlencode(&value.to_string()),
        API_VERSION,
    );
    let to_sign = format!("GET&%2F&{}", urlencode(&query));
    let mut key = config.access_key_secret.to_string().into_bytes();
    key.push(b'&');
    let signature = BASE64_STANDARD.encode(hmac_sha1(&key, to_sign.as_bytes()));
    query.push_str("&Signature=");
    query.push_str(&urlencode(&signature));

    let mut url = query;
    url.insert_str(0, "http://alidns.aliyuncs.com/?");

    let resp = http_get(&url)?;
    Ok(process_resp(&resp)?)
}

pub fn get_global_v4() -> Result<IpAddr> {
    let resp = http_get(API_GLOBAL_V4)?;
    let text = String::from_utf8(resp)?;
    Ok(IpAddr::V4(text.trim_end().parse()?))
}

fn process_resp(resp: &[u8]) -> Result<()> {
    let str = unsafe { std::str::from_utf8_unchecked(resp) };
    let mut json = json::parse(str)?;
    if let Some(msg) = json["Message"].take_string() {
        Err(anyhow!("Aliyun API error: {}", msg))
    } else {
        Ok(())
    }
}

fn http_get(url: &str) -> Result<Vec<u8>> {
    let mut easy = Easy::new();
    easy.url(url).unwrap();
    easy.timeout(CURL_TIMEOUT).unwrap();
    easy.useragent("curl").unwrap();

    let mut buf = Vec::new();

    let mut transfer = easy.transfer();
    transfer
        .write_function(|data| {
            buf.extend_from_slice(data);
            Ok(data.len())
        })
        .unwrap();
    transfer.perform().context("HTTP request failed")?;
    drop(transfer);

    Ok(buf)
}
