# Microsoft Threat Intelligence / MCP 調査

調査基準日: **2026-09-28**

本書はMDTI-MCPの実装判断に必要なMicrosoft公式資料と公開MCPを整理する。公開Web・公開GitHubを確認したもので、対象tenantでのAPI entitlement、Entra権限、実レスポンスはまだ検証していない。

## 1. 現在の対象API

実装対象はMicrosoft Graph v1.0の `microsoft.graph.security` 配下にあるMicrosoft Threat Intelligence API。

公式overview:

- https://learn.microsoft.com/en-us/graph/api/resources/security-threatintelligence-overview?view=graph-rest-1.0
- https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview?view=graph-rest-1.0

2026-08-01更新のoverviewでは、Microsoft Threat Intelligence APIはMicrosoft Defender XDRまたはMicrosoft Sentinelライセンスを持つ顧客が利用でき、API用の別ライセンスは不要と説明されている。必要権限は、delegatedが `ThreatIntelligence.Read`、applicationが `ThreatIntelligence.Read.All`。

一方、`List articles` や `Get host` 等の一部の古い個別APIページには、Defender Threat Intelligence Portal licenseとAPI add-onが必要という旧記述が残っている。

この不一致は文書だけで推測して解消しない。**MDTI-MCPでは現行overviewを設計基準にしつつ、P0で対象tenantの実アクセスをsmoke testして確定する。**

## 2. MDTI-MCPで優先するリソース

### Host enrichment

GraphのhostはIP addressまたはhostnameを表す。初期実装では以下を優先する。

```text
/security/threatIntelligence/hosts/{hostId}
/security/threatIntelligence/hosts/{hostId}/reputation
/security/threatIntelligence/hosts/{hostId}/passiveDns
```

候補としてsubdomain、WHOIS、components、ports等の関連情報もあるが、初版の必須範囲にはしない。

重要: hostモデルはIP/domain向けであり、hashやURL全体の汎用reputation APIと同じものではない。MDTI-MCPは対応していないIoC型を独自変換して「Microsoftの判定」として返さない。

### Articles

```text
/security/threatIntelligence/articles
/security/threatIntelligence/articles/{articleId}
/security/threatIntelligence/articles/{articleId}/indicators
```

記事は完成した脅威インテリジェンスを調査する中心機能。記事一覧の `$search` はMicrosoftの個別API資料上、現在single-term検索に制約されている。

MDTI-MCPでは複合queryを黙って分割して意味を変えない。初版はsingle-termを明示し、複数条件が必要な場合は対応可能なOData条件だけを型付き引数として追加する。

参考:

- https://learn.microsoft.com/en-us/graph/api/security-threatintelligence-list-articles?view=graph-rest-1.0
- https://learn.microsoft.com/en-us/graph/api/security-article-list-indicators?view=graph-rest-1.0

### Intelligence profiles

intelligence profileは脅威アクターや一般的な侵害ツール等の情報を扱う。profile本体と関連indicatorを調査フローへ組み込む。

想定する用途:

```text
actor / alias を検索
  -> profileを取得
  -> 標的・説明・関連情報を確認
  -> profileに関連するindicatorsを展開
  -> articleやhost調査へ接続
```

Graph上のIDとMicrosoftが示すaliasを保持し、名前の近さだけで別actorを同一視しない。

## 3. 公式Microsoft Sentinel MCPとの関係

Microsoftは公式のMicrosoft Sentinel MCP serverを提供している。

- https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-overview
- https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-graph-tool

Sentinel MCPはデータレイク探索、KQL、graph、incident triage等のSOC運用を中心とする。Data exploration collectionにはEntity Analyzerがあり、`analyze_url_entity` はMicrosoft threat intelligence、自組織のSentinelデータ、custom TI等を利用してAI分析を行う。

Entity AnalyzerはSecurity Copilot Contributor等の追加要件とSCU消費を伴う。これはMicrosoft Graph Threat Intelligenceの生データを決定的にreadする用途とは性質が異なる。

したがってMDTI-MCPはSentinel MCPを置き換えない。役割を次のように分ける。

```text
MDTI-MCP
  Microsoft Graph Threat Intelligence
  host / article / profile / indicators のread
  取得データと根拠をそのまま返す

Microsoft Sentinel MCP
  組織のSentinel data lake / graph / incident
  KQL探索、triage、Entity Analyzer等
```

将来Sentinel MCPも利用する場合は別のMCP接続として併存させる。

## 4. 公開コミュニティMCP

`bitbytelabio/microsoft-defender-mcp` にはGraphのintelProfiles、articles、host reputation、passive DNS等を扱う実装が公開されている。

- https://github.com/bitbytelabio/microsoft-defender-mcp

これは設計・API利用例の参考にするが、MDTI-MCPを無条件にforkする根拠にはしない。依存関係、認証方式、tool境界、企業proxy、ChatGPT接続との整合性を確認して必要な部分だけ参考にする。

`MenkW/Defender-MCP` 等のDefender管理用MCPで扱われるcustom IoC登録・削除は、Microsoft Threat Intelligenceのread APIと別領域なので本プロジェクトの対象外。

## 5. 認証

初版はバックグラウンドで安定して動くapplication permissionを想定する。

```text
Microsoft Entra application
  -> client credentials
  -> Microsoft Graph token
  -> application permission: ThreatIntelligence.Read.All
  -> https://graph.microsoft.com/v1.0/security/threatIntelligence/...
```

Entra app作成、permission付与、admin consentは環境変更なので実装と分離する。MDTI-MCPのコードやIssueへtenant secretを記録しない。

client secretを採用する場合はWindowsのOS保護ストアへ保存する。将来certificate credentialを採用できる構造にはするが、初版の必須要件にして複雑化しない。

delegated permissionは将来候補。overviewと個別APIページで表記差が残っているため、初版のdaemon用途ではapplication permissionへ絞る。

## 6. 初版で利用しないMicrosoft Graph Security機能

- Threat indicatorの登録・更新・削除。
- Defender incident / alertの更新。
- Endpoint隔離・スキャン等のDefender for Endpoint action。
- Advanced Huntingの任意KQL実行。
- Sentinel workspaceやdata lake操作。

Microsoft Graph security API全体を汎用proxy化せず、Threat Intelligenceのread endpointだけを明示登録する。

## 7. P0で実環境確認する項目

- 対象tenantがDefender XDRまたはSentinelの条件を満たし、Threat Intelligence APIへ実際にアクセスできること。
- Entra applicationへ `ThreatIntelligence.Read.All` を付与できること。
- Global Microsoft Graphで対象endpointが利用できること。national cloudは今回の初版前提にしない。
- 企業proxy / TLS環境からtoken endpointとGraphへ到達できること。
- host / articles / intelligenceProfilesから少量のreadが成功すること。
- API responseに含まれるデータをChatGPTへ渡す運用が組織・契約上許可されること。

このP0が終わるまで、公開資料にある権限・ライセンス説明を対象tenantでの動作確認済みとは扱わない。
