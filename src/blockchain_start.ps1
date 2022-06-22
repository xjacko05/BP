geth init --datadir ..\nodes\node1 genesis.json
geth init --datadir ..\nodes\node2 genesis.json
geth init --datadir ..\nodes\node3 genesis.json
geth init --datadir ..\nodes\usernode genesis.json
Set-Location ..\nodes
Start-Process bootnode -ArgumentList '-nodekey .\bootnode\boot.key -verbosity 7 -addr "127.0.0.1:30301"'
Start-Process geth -ArgumentList '--config .\node1\node1-config.toml --unlock 0xF736b20A7631498A55EC029B90396cF37B377536 --password .\node1\pw.txt --mine'
Start-Process geth -ArgumentList '--config .\node2\node2-config.toml --unlock 0xdC2567c6F6808a535A1d27Bc54bDf6D8834904Ef --password .\node2\pw.txt --mine'
Start-Process geth -ArgumentList '--config .\node3\node3-config.toml --unlock 0xFddAE37ED04CFD933FA643fAcc77b387b40b501D --password .\node3\pw.txt --mine'
Start-Process geth -ArgumentList '--config .\usernode\usernode-config.toml --unlock 0x214bdF484d62F1ca16e19ec684845f059542fed8 --password .\usernode\pw.txt'
Set-Location ..\src
