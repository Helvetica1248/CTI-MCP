# MDTI-MCP

Microsoftがインターネット上で観測したFQDN/IPの **ResolutionsとCertificates** を取得する読取専用MCP。
DefenderポータルのThreat Intelligence Insightsが利用目的であり、**自社テナントのログ検索ではありません**。

現在は0.1.0の実装レビュー段階です。実テナントのGraph利用権、ポータル表示との一致、VT-MCPとの実運用同時接続は別途確認が必要です。

## 対象と境界

```text
mdti_capabilities        ローカル設定・対応機能・当該プロセスでの確認状態
mdti_lookup_host         FQDN/IPのMicrosoft外部ホスト情報
mdti_reputation          Microsoftの原レピュテーション
mdti_resolutions         passive DNS。既定: FQDNは正引き、IPは逆引き履歴
mdti_certificates        ホストで観測された証明書と観測日時・ポート
mdti_get_certificate     証明書本体のSubject/SAN、Issuer、有効期間、fingerprint等
mdti_certificate_hosts   同じ証明書で観測された関連ホスト
```

KQL、Advanced Hunting、Sentinelログ、端末、インシデント、ユーザーのログは照会しません。
調査対象へのDNS照会・TLSハンドシェイク・HTTPアクセスも行いません。Graphが保持する情報だけを読みます。
記事・アクター検索、他社CTI、検体取得、write操作は今回の対象外です。

Entraのtenant IDは認証とAPI利用権の確認に必要ですが、テナントログの検索対象を指定するものではありません。
Graph APIが返す期間・件数・フィールドはポータルと同一とは限りません。未検出は安全判定ではありません。
`mdti_certificates` の外側の `id` はホストとの関連IDです。詳細取得には `sslCertificate.id` を渡します。

## Windowsで準備

VT-MCPとは**別フォルダ**に配置し、新しいPowerShellを開きます。Python 3.13を既定にしています。
以下はユーザーが実行するセットアップ手順であり、今回こちらから配備・権限付与は行っていません。

```powershell
Set-Location 'C:\Tools\MDTI-MCP'
.\mdti.ps1 install
.\mdti.ps1 configure
.\mdti.ps1 verify
.\mdti.ps1 doctor
```

企業proxyの入力が必要な場合は `install -ConfigureProxy` または `start-tunnel -ConfigureProxy` を使用します。
proxy情報は当該PowerShellプロセス内だけに保持します。TLS検証は無効化しません。

Microsoft Entra applicationの **application permission `ThreatIntelligence.Read.All` と管理者同意**、および対象API利用権が必要です。
app作成・権限付与は別途行ってください。ソフトウェアが自動で権限を変更する機能はありません。
`configure` ではtenant ID、client ID、client secretの「値」、AIクライアントへの結果出力の許可を入力します。
secretはWindows WinVaultのサービス名 `mdti-mcp` に保存し、設定JSONには保存しません。

非秘密の設定は `%LOCALAPPDATA%\MDTI-MCP\config.json`。
別配置は絶対パスの `MDTI_CONFIG` で指定できます。`MDTI_CLIENT_SECRET` によるプロセス環境での注入にも対応します。
汎用の `AZURE_*` やVT API keyを自動流用しません。追加CAは `MDTI_CA_BUNDLE`、専用proxyは `MDTI_PROXY_URL`。

少量の実API確認は明示指定で行います（検索結果本体はdoctorの出力に含めません）。

```powershell
.\mdti.ps1 doctor -Live -TargetHost 'google.com'
```

`doctor` の成功は指定ホストのAPI読取だけの確認です。ポータルUI全件の一致、他ホスト全件、ChatGPT経由の成功を意味しません。

## VT-MCPと同時利用

```text
                    MDTI-MCP                             既存VT-MCP
配置・venv          MDTI専用フォルダ/.venv              既存のまま
実行ファイル        mdti-mcp.exe                         vt-chatgpt-mcp.exe
tool接頭辞          mdti_                                既存のまま
Windows資格情報     mdti-mcp                             既存のまま
Tunnel profile      mdti-mcp                             vt-chatgpt-mcp等の既存profile
Tunnel ID           新しいMDTI専用ID                     既存VTのID
health URLファイル  %TEMP%\mdti-mcp-health.url            VT既存profileのファイル
health listener     127.0.0.1:0（OSが空きポートを選択）   既存のまま
```

既存VTのvenv・設定・資格情報・tunnel profileを上書きしません。既存profileに対する `--force`、プロセス停止、merge、配備は行いません。
**VTと同じTunnel IDを使わないでください。** profile名だけ違っても同じIDを使えば別MCPの接続先として分離できません。

OpenAI側でMDTI専用Tunnelを用意した後、そのruntime keyをMDTI用PowerShellの `CONTROL_PLANE_API_KEY` に設定して実行します。
これはEntraのclient secretとは別の資格情報です。既存のtunnel-clientバイナリ自体は共有できます。

```powershell
.\mdti.ps1 init-tunnel -TunnelId '<MDTI専用の新しいtunnel_id>'
.\mdti.ps1 start-tunnel
```

MDTI用ウインドウを開いたまま、VTは既存の別ウインドウで動かします。
ChatGPTではMDTI専用Tunnelを別Appとして追加し、既存VT Appと両方を利用します。
このコードはCloud側Tunnelの新規作成やVT側設定の変更を行いません。
企業CAのTunnel側取扱いはインストール済みtunnel-clientのdoctorでも確認してください。

現在の実VTインストールとの同時stdio/カタログ確認用コマンドも用意しています。

```powershell
.\mdti.ps1 coexist -VTExecutable 'C:\Path\To\vt-mcp\.venv\Scripts\vt-chatgpt-mcp.exe'
```

この確認は両実行ファイルを別プロセスで起動し、initialize/tools-listとMDTI capabilityのみを呼びます。
VT/Graphへのデータ照会や既存Tunnelの停止はしません。ChatGPTでの2つのTunnel同時接続は別のHuman試験です。

## 取得の進め方

```text
mdti_resolutions(host="example.com")
  -> FQDNの正引き履歴、firstSeen/lastSeen/collectedDateTime
mdti_resolutions(host="8.8.8.8")
  -> IPからの逆引き履歴（ライブPTR照会ではない）
mdti_certificates(host="example.com")
  -> 観測された証明書、関連IDとsslCertificate.idを区別
mdti_get_certificate(certificate_id="返されたsslCertificate.id")
  -> Subject/SAN、Issuer、有効期間等
mdti_certificate_hosts(certificate_id="同じsslCertificate.id")
  -> 共有証明書に関連するホスト。共有だけで同じ攻撃者とは断定しない
```

1回の一覧取得は既定50・最大200件。`next_cursor` があれば同じhost/方向/limitまたは同じ証明書ID/limitで続けます。
カーソルは10分有効、サーバー再起動で失効します。上流継続URLはモデルに公開せず、同一Graphリソースだけに追従します。
結果サイズで切り分けた残りもカーソルに保持し、黙って捨てません。単一レコード自体が大きすぎる場合は明示エラーです。

## 開発・検証

```powershell
.\mdti.ps1 install
.\mdti.ps1 verify
```

Linux等では `python -m pip install '.[test]'`、`python -m pytest -q`、`mdti-mcp audit-tools`。
テストのGraph応答は合成データです。SDKが未導入の場合はSDKテストがskipされるため、coreだけのPASSをMCP起動成功としません。
CIはSDKのimportを必須にし、Linux/Windowsでカタログと独立2プロセスのstdio試験を実行します。

MCP SDK 1.30.0、Microsoft MSAL、HTTPX、keyringを依存として流用します。独自のOAuth/MCPプロトコルは実装しません。
SDK 1.xは保守ラインで、既存VTとの運用整合のため固定しています。依存更新はMDTI専用venvで検証します。

[設計](docs/design.md) / [API出典・流用元](docs/mdti-research.md) / [Issue #1](https://github.com/Helvetica1248/MDTI-MCP/issues/1)

未確認事項: 実tenant API利用権、実Windows WinVault/proxy、実VTとの併用、ChatGPT接続、ポータルUIとの表示比較、Human判定。
