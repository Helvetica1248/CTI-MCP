# MDTI-MCP

Microsoft Threat Intelligence（旧称 Microsoft Defender Threat Intelligence / MDTI 系）の Microsoft Graph API を、ChatGPT等のMCPクライアントから**読取専用で調査・探索する**ためのプロジェクト。

**現在は設計段階です。MCPサーバー本体、実API接続、Windows/ChatGPTでの動作確認は未実施です。**

## 方針変更

当初はAhnLab、BAE、ESET、Falcon Intelligence、Kaspersky、Microsoft、PwC、TeamT5を横断するCTI-MCPを検討しましたが、単純なIoC横断照会は既存のIoC Lookupツールで実用上十分と判断しました。

このリポジトリでは重複実装を避け、**Microsoft Threat Intelligenceの調査機能に限定**します。既存IoC Lookupは複数CTIの定型照会、MDTI-MCPはMicrosoftの脅威記事・アクタープロファイル・ホスト情報・関連IoCを辿る探索用途と役割を分けます。

## 対象

- IP / domain のhost情報、reputation、passive DNS等の読取。
- Microsoft Threat Intelligenceの記事検索・取得と関連indicator。
- intelligence profile（脅威アクター・ツール等）の検索・取得と関連indicator。
- 必要に応じてWHOIS、subdomain、component等のGraph Threat Intelligenceリソースへ段階的に拡張。

初版ではhash/URLを含む汎用レピュテーションAPIを独自に擬似実装しません。Microsoft Graphが提供するデータモデルに沿って機能を公開します。

## 対象外

- AhnLab / BAE / ESET / Falcon / Kaspersky / PwC / TeamT5の再実装。
- VirusTotal機能の再実装。検体関連は既存VT-MCPを利用。
- Microsoft Defender for Endpointの端末操作、IoC登録・削除、隔離等のwrite操作。
- 検体提出・ダウンロード・sandbox実行。
- Microsoft SentinelデータレイクのKQL探索やSecurity Copilot Entity Analyzerの代替。

## 資料

- [Microsoft Threat Intelligence / MCP調査](docs/mdti-research.md)
- [MDTI-MCP 実装方針](docs/design.md)
- [Issue #1: 段階的実装計画](https://github.com/Helvetica1248/MDTI-MCP/issues/1)

## 基本境界

- Microsoft GraphのThreat Intelligence読取APIだけを明示的に公開する。
- 任意Graph URL、任意OData式、shell、任意HTTP requestをMCP toolとして公開しない。
- アプリケーション権限は `ThreatIntelligence.Read.All` を第一候補とする。
- API secret等はWindowsのOS保護ストアを利用し、GitHub・tool引数・ログへ出さない。
- 企業proxy / 独自CA環境でもTLS検証を維持する。
- Microsoftの原データ、取得時刻、検索範囲、ページング/打切りを保持し、MCP側で根拠のない悪性/安全判定へ変換しない。

実装、実API試験、Windows/ChatGPT接続、Human判定、merge、配備はそれぞれ別状態として記録します。
