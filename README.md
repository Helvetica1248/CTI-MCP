# CTI-MCP

有償の脅威インテリジェンスをChatGPT等のMCPクライアントから横断照会するための調査・設計プロジェクト。

**現在は設計提案の段階です。MCPサーバー本体は未実装で、実API・Windows・ChatGPTでの動作確認も未実施です。**

## 資料

- [各社のMCP・API調査](docs/provider-survey.md) — 2026-09-28時点の一次資料、対象製品の違い、公開確認できた範囲。
- [実装方針](docs/design.md) — 構成、共通tools、原判定・根拠、部分失敗、認証、キャッシュ、必要十分な検証。
- [Issue #1: 段階的実装計画](https://github.com/Helvetica1248/CTI-MCP/issues/1) — 受入条件、未確認事項、承認・進捗の正本。

## 対象

AhnLab TIP / ATIP、BAE Systems Threat Intelligence、ESET Threat Intelligence、CrowdStrike Falcon Intelligence、Kaspersky、Microsoft MDTI系データ、PwC Threat Intelligence、TeamT5 ThreatVision。

## 提案の要点

独立したPython製stdio MCPに共通の検索・取得toolsを設け、各社のAPI/SDKと、必要なMISP/TAXIIフィードの索引をprovider adapterで接続します。

各社の原判定と根拠を保持し、未検出・権限不足・未照会・エラー・古い索引を区別します。既存MCPがある場合も、対象製品と取得できる情報を確認して利用します。

初期対象は少量のIoC照会です。レポート検索・取得、アクター・関連情報を段階的に追加します。具体的な実装順と承認はIssue #1で管理します。

公開資料にはAPI key、契約本文、有償レポート、実IoCフィード、添付ツールのDBを含めません。実資格情報や契約上の利用範囲は、対象providerの実装・接続確認時に扱います。
