# aliddns-rs

aliddns-rs is a Rust program providing DDNS service through [Aliyun Open API](https://www.aliyun.com/product/openapiexplorer), running as console program or **Windows service**.

## Usage

Extract the release into an individual directory, modify `config.toml` as instructed in the file, and then run the executable.

If it works, you can follow the instructions below to register it as a Windows service.

## Windows Service Setup

### Automatic Setup

Run `manage_service.bat` as administrator and follow the instructions.

### Manual Setup

Run the command below as administrator to register the service.

`sc create AliDDNS binPath="C:\path\to\aliddns.exe -srv" start=auto`

And then start the service.

`sc start AliDDNS`

Check `log.txt` in the directory of executable. There should be log output in it.
