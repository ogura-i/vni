# vni
vni は Mint 上で走行するOS間で通信するための仮想ネットワークネットワークインタフェースである

# install
1. clone this repository
```
$ git clone git@github.com:ogura-i/vni.git 
```

2. move this driver to Mint
```
$ mv vni ~/xxxx/Mint/driver/net/.
```

3. compile Mint


# 起動方法
1. 先行OSで sn0 をロードする
```
$ sudo ifconfig sn0 local0
```
2. 後続OSで sn1 をロードする
```
$ sudo ifconfig sn1 local1
```

