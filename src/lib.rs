use anyhow::{anyhow, Context, Result};
use chrono::{SecondsFormat, Utc};
use curl::easy::Easy;
use hmacsha1::hmac_sha1;
use serde::Deserialize;
use std::net::IpAddr;
use std::time::Duration;
use urlencoding::encode as urlencode;

const API_VERSION: &str = "2015-01-09";
const SIGNATURE_METHOD: &str = "HMAC-SHA1";
const SIGNATURE_VERSION: &str = "1.0";
const ACTION: &str = "UpdateDomainRecord";
const API_GET_IP_V4: &str = "http://members.3322.org/dyndns/getip";
const CURL_TIMEOUT: Duration = Duration::from_secs(1);

pub mod ifaddrs;
mod sockaddr;

#[derive(Deserialize)]
pub struct Config {
    pub interval_secs: u64,
    #[serde(default)]
    pub ipv6: bool,
    pub access_key_id: String,
    pub access_key_secret: String,
    pub record_id: u64,
    pub rr: String,
}

pub fn update(config: &Config, value: &IpAddr) -> Result<()> {
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
        config.record_id,
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
    let signature = base64::encode(hmac_sha1(&key, to_sign.as_bytes()));
    query.push_str("&Signature=");
    query.push_str(&urlencode(&signature));

    let mut url = query;
    url.insert_str(0, "http://alidns.aliyuncs.com/?");

    let resp = http_get(&url)?;
    Ok(parse_response(&resp)?)
}

pub fn get_ip_v4() -> Result<IpAddr> {
    let resp = http_get(API_GET_IP_V4)?;
    let str = unsafe { std::str::from_utf8_unchecked(&resp[..resp.len() - 1]) };
    Ok(IpAddr::V4(str.parse()?))
}

fn parse_response(resp: &[u8]) -> Result<()> {
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
    std::mem::drop(transfer);

    Ok(buf)
}
