# MDTI-MCP: 外部ホスト情報の読取設計

2026-09-28の追加指示を優先。目的はFQDN/IPのThreat Intelligence Insightsに相当する **Resolutions / Certificates** の取得。
設計PR #2を基点とし、記事・アクター中心の旧計画は今回の実装対象から外す。
実装・承認・試験状況の正本は [Issue #1](https://github.com/Helvetica1248/MDTI-MCP/issues/1)。

## 境界

```text
ChatGPT/任意MCPクライアント
  -> MDTI専用Tunnel (別ID/profile) またはstdio
  -> 公式MCP Python SDK
  -> 固定のMicrosoft Graph Threat Intelligence read endpoint

Entra client credentials -> 公式MSAL -> Graph用token
```

Entra tenantは認証/利用権の文脈。自社ログ、Advanced Hunting、KQL、Sentinel、端末管理、インシデントにアクセスしない。
調査対象hostへのDNS、TLS、HTTP接続はしない。stdioサーバーはTCP listenerを開かない。

## 実装対象

7ツール: capabilities、host、reputation、resolutions、certificates、certificate詳細、certificate関連hosts。
ResolutionsのautoはFQDN→passiveDns、IP→passiveDnsReverse。方向は引数/結果に明示。
ホスト証明書の関連IDとsslCertificate.idを区別し、観測日時・ポート・Subject/SAN・Issuer・期間等の原データを保持。
欠落フィールドを推測しない。証明書共有は攻撃者の同一性を証明しない。原レピュテーションを独自に再スコアリングしない。

## API・結果

Graph v1.0 global cloudのみ。固定したGET操作とtenant限定の認証通信だけを許可。
任意Graph/OData/KQL引数、未知endpoint、write操作は公開しない。
IP/FQDNは構文検証し、private/local/URL/hashはhost引数として拒否。URLからhostへ黙って変換しない。

結果はschema version、source、operation、query、retrieved_at、data、source_url、status、next_cursor、has_more等。
取得時刻とMicrosoftのfirstSeen/lastSeen/collectedDateTimeを分離する。
not_found、not_configured、policy_blocked、unauthorized、forbidden、rate_limited、timeout、upstream_error等を分ける。

一覧は1回1上流ページ。既定50件、上限200件。上流ページ内の超過分を捨てず次のカーソルへ保持。
カーソルはプロセス内・10分・64個/16MiBまで、リソースとlimitに束縛。失効/不一致は明示エラー。
Graph nextLinkは同じhttps originかつ同じresource pathのみ許可。ユーザーにはURLでなくopaque cursorを返す。
HTTP応答2MiB、tool応答256KiBを上限とし、単一巨大レコードは明示エラー。永続TI cache/DB/全文索引はない。

API呼出しは最大同時4、全体30秒。HTTP connect 5秒/read 20秒。429/5xxは短いRetry-Afterで最大2回再試行。
401のtoken更新は1回。403は未検出に変換せず再試行もしない。生の上流エラー本文や例外reprを外へ返さない。

## 設定・併用

専用venv、mdti_ tool名、`mdti-mcp` Windows WinVault、専用LOCALAPPDATA config、専用Tunnel ID/profileとhealthファイル。
VTのコード、venv、プロセス、資格情報、profileは変更しない。tunnel-clientバイナリの共有だけは可能。
共通ネットワーク変数をランチャー実行中に適用する場合は当該プロセスのみとし、終了時に戻す。

Windows helperはUTF-16LE BOM、PythonはUTF-8 BOMなし。
secret/tokenは設定JSON・ログ・GitHubへ保存しない。MSAL token cacheはメモリのみ。
OS保護資格情報が使えない場合は平文backendへfallbackしない。環境注入はMDTI専用変数で明示する。
AI出力の運用確認はconfigureのallow_ai_outputで記録し、未確認時は実データ読取を拒否する。
TLS検証を維持し、企業CA/proxyに対応。秘密値・原response全文を診断ログへ出さない。

## 受入条件

Machine: 入力、方向、観測日時、証明書ID、上流エラー、ページング、出力上限、endpoint隔離、tools/list、stdioを重点試験。
実VT: installed executableを使った別プロセスinitialize/list-tools、名前衝突なしをcheck_coexistenceで確認。
Human: 実tenant API、ポータルのResolutions/Certificatesとの比較、VTとMDTIの両Appを使うChatGPTセッション。
UI/APIの完全一致は未保証。UI閲覧権だけでAPI権限の存在を推定しない。P0未確認でも合成データによる実装/テストは可能。

対象外: 他社CTI再統合、記事/アクター検索、サンプル取扱い、テナントログ、権限変更、merge/配備。
