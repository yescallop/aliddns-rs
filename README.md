# aliddns-rs
aliddns-rs is a Rust program providing DDNS service through [Aliyun Open API](https://www.aliyun.com/product/openapiexplorer), running as console program or **Windows service**.

## Usage
Modify `config.toml` as instructed in the file, put the executable in the same directory, and then run it.

If it works, you could follow the instruction below to register it as a Windows service.

## Windows Service Setup

Run the command below as administrator to register the service.

`sc create AliDDNS binPath="C:\path\to\aliddns.exe -srv" start=auto`

And then start the service.

`sc start AliDDNS`

Check `log.txt` in the directory of executable, there should be log output in it.