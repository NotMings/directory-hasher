# directory-hasher
用于生成目录下所有文件哈希的生成器

可以对复制后的文件夹进行完整性检查

仅在 linux 上可用

## 使用方法
### 前置条件

 openssl/sha.h 库

`apt install -y libssl-dev`

### 编译
需要 c99 或以上

`gcc hasher.c -o hasher -lcrypto`

### 运行

`./hasher <path>`

如果不填目录，则检查当前目录