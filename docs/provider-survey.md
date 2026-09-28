# 有償CTIのMCP・API調査

調査日: **2026-09-28** / 対象: ユーザー指定の8サービス

公開Web、ベンダー/実装元の公式ドキュメント、公開GitHubのREADMEと必要な実装を確認した。添付IoC Lookupは静的に参照した。**実API認証、課金を伴う照会、契約者ポータルの閲覧は行っていない。** 本書のAPI機能はユーザー契約での利用権や動作確認を意味しない。

## 1. 結果一覧

「未確認」は調査範囲内で公開実装を確認できなかったという意味。非公開・顧客限定の提供まで不存在とは判断しない。「別製品」は同じ社名のMCPが見つかっても、対象CTIを利用する証拠がないもの。

| 対象CTI | 公式・ベンダー管理MCP | コミュニティMCP | 実装方針 |
| --- | --- | --- | --- |
| AhnLab TIP / ATIP | TIP向けは未確認 | TIP向けは未確認。BICScanは別製品 | 契約対象のTIP REST API |
| BAE Systems Threat Intelligence | 未確認 | 未確認 | 現行契約でMISPが利用可能なら同期索引。詳細APIは要確認 |
| ESET Threat Intelligence | ETI向けは未確認 | PROTECT等の管理用はあるが、ETI向けは未確認 | APIv2、APT/eCrime MISP、TAXIIを別capabilityにする |
| Falcon Intelligence | **CrowdStrike/falcon-mcp**。ベンダー管理OSS、公式製品ではない旨を明記 | 第三者のCrowdStrike MCPはあるが、確認例はEDR/IoC管理用。Falcon Intelligence専用は未確認 | FalconPy Intelを中心に共通adapter化 |
| Kaspersky | **公式OpenTIP MCPあり**。有償TIP全機能のMCPは未確認 | 有償TIP全体を扱う独立実装は未確認 | OpenTIPと企業向けThreat Lookup/TIPを分離 |
| Microsoft MDTI系 | **公式Sentinel MCPあり**。MDTI Graph API全体の直接公開とは異なる | **bitbytelabio/microsoft-defender-mcp**にMDTI実装あり | 現行Graph Threat Intelligence API |
| PwC Threat Intelligence | 未確認 | 未確認 | 現行REST API。report/IoC feedとenrichment |
| TeamT5 ThreatVision | 未確認 | 未確認 | OAuth2 REST API。公開OpenCTI connectorを設計参考にする |

したがって、**既存MCPを8社分接続すれば完成する状況ではない**。共通MCPの上に各API/SDKと必要なフィード索引を接続する構成が適する。詳細は [設計案](design.md)。

## 2. AhnLab TIP / ATIP

### MCP

[ahnlabio/bicscan-mcp](https://github.com/ahnlabio/bicscan-mcp) は公開されているが、ブロックチェーンアドレス・dApps等のBICScan向けであり、AhnLab TIPのMCPには数えない。TIP対象の公式/コミュニティMCPは公開未確認。

### API・取得範囲

2026-07-22の公式解説に、独立したAhnLab TIP APIのREST提供がある。IP、URL、domain、file hashの照会と、リスク・検知名・観測時刻等が対象。現行記事にはMD5/SHA-256が明示され、詳細API仕様は顧客向けに提供される。利用量に応じたプランがある。[公式API解説](https://www.ahnlab.com/en/contents/content-center/36234)

製品全体としてactorや脅威研究等の機能があるが、それらすべてが同じAPI/SKUで取得できることまでは確定していない。[製品ページ](https://www.ahnlab.com/en/product/threat-intelligence)

### 提案と未確認点

IoC照会から開始し、認証、base URL、response mapping、SHA-1対応、pagination/quotaを現行契約者資料で確定する。レポート・actorは個別capabilityとして追加する。

添付のAhnLab connectorはREADME自身がbest effortと記載している。旧endpointとfield mappingを現行仕様や動作済み実装として採用しない。

## 3. BAE Systems

### MCP・APIの公開状況

専用の公式/コミュニティMCP、公開API仕様、公式SDKは確認できなかった。

現行BAE Systems Digital Intelligenceの製品ページは、技術データフィードと文脈を付けたレポートをsecure portalで提供すると説明する。これだけで、任意IoCの即時API照会や全文検索APIの存在は確定しない。[BAE公式製品ページ](https://www.baesystems.com/en/product/threat-intelligence)

### 旧添付から分かること

BAEのMISPをPyMISPで読み、日付条件付きでイベントをSQLiteへ同期するコードがある。現行のMISPアクセス、API利用権、全件取得の成功を今回確認したわけではない。

### 提案と未確認点

現在の契約でもMISPが提供されるなら、MISPイベント→IoC/根拠索引→MCP検索を第一候補とする。event/attribute UUID、report参照、時刻、タグ・Galaxy、markingを保持する。

レポートへのリンクがあることと、本文をAPI取得できることは分ける。同期期間・更新時刻・取得漏れを応答に示す。現行MISPの認証方式/権限/保持範囲と、正規のreport取得方法を契約者資料で確認する。

## 4. ESET Threat Intelligence

### MCP

[maciekaz/ESET-MCP](https://github.com/maciekaz/ESET-MCP) と [Fenrindale/eset-protect-mcp](https://github.com/Fenrindale/eset-protect-mcp) を確認した。対象はPROTECT/Connect/Inspect等の管理機能。前者は独立コミュニティプロジェクトと明示されている。**ETIの有償レポート・フィード検索MCPの存在証拠にはならない。** ETI専用MCPは公開未確認。

### APIは一つではない

公式にETI APIv2とSwaggerが案内されている。今回Swaggerの操作一覧本文は取得できていないため、全endpointを検証済みとはしない。[APIヘルプ](https://help.eset.com/eti_portal/en-US/api.html)

| 接続 | 認証 | 用途 |
| --- | --- | --- |
| ETI APIv2 | Bearer API Token | 契約対象のレポート等の操作 |
| APT MISP | APT用API key | APTイベント・IoC・レポート参照 |
| eCrime MISP | eCrime用Auth key | eCrimeイベント等。APT用の鍵とは別 |
| TAXII | 専用Basic認証 | STIXフィード |

認証情報の分離は公式に説明されている。[Access Credentials](https://help.eset.com/eti_portal/en-US/access_credentials.html)

ESETはread-only MISPアカウントとAPI/PyMISPを案内する。MISP Eventのreport UUIDから、次のAPIv2経路によるPDF取得が文書化されている。[MISPヘルプ](https://help.eset.com/eti_portal/en-US/misp.html)

```text
GET /api/v2/apt-reports/{reportUuid}/files
GET /api/v2/apt-reports/{reportUuid}/download/pdf
```

TAXII 2.1 / STIX 2.1が利用可能で、公式サンプルがある。feed側の保持期間は14日、`added_after`を指定しない取得は過去2日。これを自組織の保存権限や全レポートの履歴期間と同一視しない。[Data Feeds](https://help.eset.com/eti_portal/en-US/taxii_feeds.html)

### 検索・quota・契約

IoC Searchはpreviewとして記載され、90日の保持、顧客あたり週300検索、IoC種別ごとの結果上限100件がある。これはIoC Searchの説明であり、API全体に一律適用されるquotaとは断定しない。[IoC Search](https://help.eset.com/eti_portal/en-US/ioc_search.html)

API全体のFair Useは毎分180 request（認証時はuser単位、未認証時はIP単位）という別制限がある。feedにも別条件があるため個別設定する。[Fair Use Policy](https://help.eset.com/eti_portal/en-US/fair_use_policy.html)

Data Feeds、APT/eCrime Reports、Advanced/Ultimate等で権限・過去レポート範囲が異なる。全文未契約でpreviewだけを取得できる場合もある。[Subscriptions](https://help.eset.com/eti_portal/en-US/eti_licenses.html)

### 提案

`eset_api` / `eset_apt_misp` / `eset_ecrime_misp` / `eset_taxii`をESET内の別capabilityにする。まず現行契約でMISP検索とreport UUID→APIv2取得を確認し、IoC直接検索は対応endpointを確認して追加する。TAXII同期はMCP lookupと別プロセスとする。

## 5. CrowdStrike Falcon Intelligence

### ベンダー管理MCP

[CrowdStrike/falcon-mcp](https://github.com/CrowdStrike/falcon-mcp) はベンダー管理のOSS。公式CrowdStrike製品ではないとの明記があるが、通常のTechnical Support窓口は案内されている。**「非公式な第三者実装」や「サポートなし」とは一括分類しない。** [SUPPORT.md](https://github.com/CrowdStrike/falcon-mcp/blob/main/SUPPORT.md)

Intelモジュールには、次のCTI検索が実装されている。

```text
falcon_search_actors
falcon_search_indicators
falcon_search_reports
falcon_get_mitre_report
```

必要なscopeは利用機能に応じた `Actors (Falcon Intelligence): READ`、`Indicators (Falcon Intelligence): READ`、`Reports (Falcon Intelligence): READ`。レポート検索はタイトル・説明等のメタデータであり、本文PDFを返す機能とは別。[Intelモジュール文書](https://developer.crowdstrike.com/falcon-mcp/modules/intel/)、[実装](https://github.com/CrowdStrike/falcon-mcp/blob/main/falcon_mcp/modules/intel.py)

### 統合adapterの候補

第三者の [vinayakcyber/crowdstrike-mcp](https://github.com/vinayakcyber/crowdstrike-mcp) も実在する。ただし確認したIoC操作は `/iocs/queries/indicators/v1` と `/iocs/entities/indicators/v1` で、Falcon Intelligenceの `/intel/*`、アクター、有償レポートを扱う実装は同ファイルに見当たらない。今回のCTI対応MCPとしては計上しない。[crowdstrike_api.py](https://github.com/vinayakcyber/crowdstrike-mcp/blob/main/crowdstrike_api.py)

CrowdStrike管理のPython SDK [FalconPy](https://github.com/CrowdStrike/falconpy) の `Intel` を第一候補とする。MCPの検索操作に加え、APIには `GetIntelReportPDF` / `Intel.get_report_pdf` / `GET /intel/entities/report-files/v1` があり、report IDから本文を取得する経路を作れる。[Intel API reference](https://developer.crowdstrike.com/api-reference/collections/intel/)

### 提案と未確認点

最初のadapterに向く。IoC照会から始め、report search/get、actor検索へ拡張する。Falcon Query LanguageへのIoC埋込みは専用escapingで扱う。API region、3種のREAD scope、契約利用権は実アカウントで確認する。

`falcon-mcp`単体を比較用に起動する場合は、確認した版を固定し、Intelモジュールとread-only設定に限定する。広範なEDR/管理用toolsをCTI-MCPへ自動取り込みしない。

## 6. Kaspersky

### 公式MCPはOpenTIP向け

[KasperskyLab/threat-intelligence/opentip-mcp](https://github.com/KasperskyLab/threat-intelligence/tree/master/opentip-mcp) のREADME・実装を確認した。接続先は `opentip.kaspersky.com/api/v1/`、認証は `x-api-key`、stdioのPython実装。[README](https://github.com/KasperskyLab/threat-intelligence/blob/master/opentip-mcp/README.md)

| tool | 動作 |
| --- | --- |
| `search_hash` / `search_ip` / `search_domain` / `search_url` | 既存情報の検索GET |
| `get_full_analysis_result` | 既存のファイル分析結果取得POST |
| `analyze_file` | ローカルファイルを開き、scan APIへ提出POST |

4検索toolから `analyze_file` を呼ぶ経路はコード上ない。ただしAPIサービス内部の能動URL調査等まで、このコードから断定はしない。[opentip.py](https://github.com/KasperskyLab/threat-intelligence/blob/master/opentip-mcp/opentip.py)

**このMCPは企業向け `tip.kaspersky.com` のレポート・actor・commercial feed全体を扱うものではない。** OpenTIP接続だけで、購入済み有償CTIへの対応完了とはしない。

### 有償API

Threat LookupにはREST APIがあり、hash/IP/domain/URLを扱う。SKUで利用回数・情報範囲等が異なる。公式製品条件には内部業務目的や再公開等の制限があり、コードのライセンスとデータ利用権は別に扱う。個別のChatGPT送信可否は、本調査だけでは確定しない。[Threat Lookup Product Terms](https://media.kaspersky.com/documents/msa_terms/Kaspersky_Threat_Lookup.Product_Terms_and_Conditions.pdf)

レポート系サービスは別途存在するが、必要なAPI/ライセンスは契約者仕様で確認する。[Threat Intelligence Reporting](https://www.kaspersky.com/enterprise-security/threat-intelligence-reporting)

### 提案

`kaspersky_opentip` と `kaspersky_tip` を分離する。有償契約のThreat Lookupを優先して仕様確認し、OpenTIP版は参考または別の補助機能とする。upload toolは初版の読取toolsに含めない。有償reports/actors/feedsは個別capabilityとして追加する。

## 7. Microsoft MDTI / Microsoft Threat Intelligence

### 現行ライセンス資料の更新

**2026-08-01更新のGraph API overviewでは、Microsoft Defender XDRまたはMicrosoft Sentinelライセンスの顧客がThreat Intelligence APIを利用でき、別ライセンスは不要と説明されている。** アプリケーション権限は `ThreatIntelligence.Read.All`。旧MDTI単独製品の移行を、Graph API全廃と同一視しない。[現行API overview](https://learn.microsoft.com/en-us/graph/api/resources/security-threatintelligence-overview?view=graph-rest-1.0)

一方、個別の旧APIページにはPortalライセンス/API add-onの記述が残る。現行overviewを基準としつつ、文書の不一致とtenantでの確認が必要であることを記録する。[List articles](https://learn.microsoft.com/en-us/graph/api/security-threatintelligence-list-articles?view=graph-rest-1.0)

Defenderの新しいThreat intelligence画面はOverview/Intel explorerで構成される。旧ポータルの画面URLに接続実装を依存させない。[現行機能](https://learn.microsoft.com/en-us/defender-xdr/defender-threat-intelligence)、[移行案内](https://learn.microsoft.com/en-us/defender-xdr/threat-intelligence-transition)

### 公式Sentinel MCP

Microsoftは公式ホスト型Sentinel MCPを提供している。主な用途は組織データ探索・triage等で、Entra認証・必要role・環境要件がある。[公式MCP overview](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-overview)、[前提条件](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-get-started)

Data explorationにはMicrosoft TI等を参照する `analyze_url_entity` があるが、AIによる分析ジョブであり、MDTI Graph全体の単純な読取ラッパーではない。Entity analyzerにはSecurity Copilot ContributorとSCU消費が案内されている。[Data exploration tools](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-data-exploration-tool)

### MDTIを扱うコミュニティMCP

[bitbytelabio/microsoft-defender-mcp](https://github.com/bitbytelabio/microsoft-defender-mcp) は、GraphのintelProfiles、articles、host reputation、passive DNS等を呼ぶ実装を持つ。READMEと `src/server.rs` を確認した。存在と実装範囲の確認までで、ビルド・品質監査・実接続は未実施。[実装](https://github.com/bitbytelabio/microsoft-defender-mcp/blob/main/src/server.rs)

一方、[MenkW/Defender-MCP](https://github.com/MenkW/Defender-MCP) のIoC登録・削除等はMDE側のカスタムIoC管理であり、MDTI検索と分ける。

### 推奨APIと制約

Graph v1.0の `/security/threatIntelligence/` に対する専用adapterを作り、最初はIP/domain、記事、actor profileと関連IoCを扱う。

```text
articles
articles/{id}
articles/{id}/indicators
intelProfiles
intelProfiles/{id}/indicators
hosts/{id}/reputation
hosts/{id}/passiveDns
```

hostはIPまたはdomainのモデルで、任意hash/URL全体の汎用reputationと同じ能力ではない。[Host](https://learn.microsoft.com/en-us/graph/api/resources/security-host?view=graph-rest-1.0)

記事には本文や要約、profileには別名・標的等がある。[Article](https://learn.microsoft.com/en-us/graph/api/resources/security-article?view=graph-rest-1.0)、[Intelligence profile](https://learn.microsoft.com/en-us/graph/api/resources/security-intelligenceprofile?view=graph-rest-1.0)

記事一覧の `$search` は文書上単一語の制約がある。共通の複合queryを黙って渡さず、providerが対応する検索と、取得済み集合への追加filterを区別する。無制限に全記事を取り込む代替策は採用しない。[List articles](https://learn.microsoft.com/en-us/graph/api/security-threatintelligence-list-articles?view=graph-rest-1.0)

初版はアプリケーション権限とclient credentialsを想定する。必要なEntraの権限付与・admin consentは、別途承認された環境設定として実施する。今回その操作はしていない。

## 8. PwC Threat Intelligence

### MCP・APIの根拠

公式/コミュニティMCPは公開未確認。[PwC Threat Intelligence Portal](https://threatintel.io/) は確認できるが、公開された完全な公式API仕様/SDKは確認できなかった。

Vertexが提供するSynapse Power-Upは、PwC APIを使ったFQDN、IPv4、MD5/SHA-1/SHA-256のenrichment、IoC feed、report feed、report detail/PDF、関連YARAを文書化する。これは**その連携実装の一次資料**であり、PwC自身のAPI全仕様でもMCPでもない。[Vertex package docs](https://synapse.docs.vertex.link/projects/rapid-powerups/en/latest/storm-packages/synapse-pwc-threatintel/stormpackage.html)

client ID/secretによる認証が案内される。[管理者向け資料](https://synapse.docs.vertex.link/projects/rapid-powerups/en/latest/storm-packages/synapse-pwc-threatintel/adminguide.html)

### 提案と未確認点

既存添付のtoken/Bearer方式を参考に、現行REST仕様との照合から始める。IoC照会とreport feed→detail→IoCを優先する。全文検索API、URL/IPv6照会、各quotaは未確認。

feedを索引化して検索する場合は、同期期間・時刻・対象範囲を明示する。Vertexの変更履歴には応答のnullやpagination項目への対応があるため、古い添付の応答形式が維持されていると仮定しない。[変更履歴](https://synapse.docs.vertex.link/projects/rapid-powerups/en/latest/storm-packages/synapse-pwc-threatintel/changelog.html)

## 9. TeamT5 ThreatVision

### 対象製品とMCP

添付の明示名と公開connectorから、対象は**TeamT5 ThreatVision**と特定できる。同名の別製品ではない。専用の公式/コミュニティMCPは公開未確認。

公式FAQは、ほぼ全機能がAPIで利用でき、詳細は契約者プラットフォーム内にあると説明する。[公式製品ページ・FAQ](https://teamt5.org/en/platform/threatvision)

### 公開連携実装

TeamT5はOpenCTI統合を公式発表している。[公式発表](https://teamt5.org/en/posts/teamt5-s-threatvision-now-integrated-with-filigran-s-open-cti/)

公開OpenCTI connectorはOAuth2 Client Credentialsを推奨し、事前取得Bearer token方式は互換用としてdeprecatedとされる。Reports/Indicator Bundlesを中心に、関連STIX objectやrelationshipsを取り込む。**MCPではないが、現行認証・取得方法を調べる参考になる。** [connector README](https://github.com/OpenCTI-Platform/connectors/blob/master/external-import/teamt5/README.md)

### 提案と未確認点

OAuth2 REST adapterを作り、IoC・report・関連情報を契約APIの提供範囲に応じて追加する。検索条件、対応IoC種別、全文取得、quotaはプラットフォーム内仕様で確定する。

公開connectorのTLP設定既定値を、手元の契約データが外部公開可能という根拠にしない。元データのmarkingと契約上の取扱いを保持する。

## 10. 調査の確認範囲と限界

主な検索は製品名と `MCP` / `Model Context Protocol` の組合せ、GitHub repository/code検索、公開APIドメインと `mcp` の組合せ。検索で見つかったものはベンダー/開発元のREADME・文書または実装で製品範囲を確認した。

| 製品 | 代表検索・確認対象 |
| --- | --- |
| AhnLab | AhnLab MCP、AhnLab TIP MCP、AhnLab TIP API、BICScan README |
| BAE | BAE Systems MCP threat、BAE threat MCP、baesystems.com mcp、公式製品 |
| ESET | ESET Model Context Protocol、ESET threat intelligence mcp、PROTECT/ETI docs |
| Falcon | CrowdStrike/falcon-mcp、Intel module、FalconPy Intel、第三者Falcon MCP |
| Kaspersky | Kaspersky MCP、公式threat-intelligence/opentip-mcpのREADME・実装 |
| Microsoft | Sentinel MCP公式docs、MDTI Graph、microsoft-defender-mcp実装 |
| PwC | PwC threat MCP、threatintel.io mcp、Synapse PwC package |
| TeamT5 | ThreatVision MCP、TeamT5 MCP、threatvision mcp.server、OpenCTI connector |

MCPのディレクトリ掲載だけでは存在・範囲・安全性・保守品質を確認したことにしない。バージョン/commit固定、依存ライブラリ検査、live API smokeは実装段階で実施する。公開未確認のproviderは、ベンダーに顧客限定MCPの提供有無を問い合わせる余地がある。

## 11. 実装に必要な確認事項

| provider | 実装前に必要な非秘密情報 |
| --- | --- |
| AhnLab | 契約APIプラン、最新API仕様、hash種別、report/actor取得範囲 |
| BAE | 現行MISP提供/権限、取得対象collection、report本文の正規取得手段 |
| ESET | ETI tier、APIv2/MISP/TAXII/IoC Searchの権利、report履歴範囲 |
| Falcon | cloud region、Actors/Indicators/Reports READ scopeとAPI利用権 |
| Kaspersky | OpenTIPと有償TIPの区別、Threat Lookup/Reporting等の契約機能 |
| Microsoft | 現在のDefender XDR/Sentinel権利、Graph app permission、tenant検証 |
| PwC | 現行API文書、client認証、report/IoC feed、検索とpagination仕様 |
| TeamT5 | 現行APIv2仕様、OAuth client、対象情報、検索条件とquota |

各社共通で、保存・AI処理・出力の許可範囲を確認する。API keyやsecretをIssue/PRに貼り付ける必要はない。未確認事項があることは、本書の公開・共通基盤の設計を止める理由にはしない。
