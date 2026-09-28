# 外部ホスト情報API・流用元

確認日: 2026-09-28。ユーザー提示のDefender Threat Intelligence Insightsの画面を目的として参照。
ログインCookieの抽出、非公開UI APIのリバース、提示URLのtenant IDのコード埋込みは行わない。
以下は公開公式APIとの機能対応であり、ユーザーtenantの実API利用権やUIとの全件一致は未検証。

## API対応

```text
Resolutions / FQDN     GET /hosts/{hostId}/passiveDns
Resolutions / IP       GET /hosts/{hostId}/passiveDnsReverse
Certificates          GET /hosts/{hostId}/sslCertificates
証明書詳細            GET /sslCertificates/{sslCertificateId}
証明書の関連hosts     GET /sslCertificates/{sslCertificateId}/relatedHosts
ホスト/判定           GET /hosts/{hostId} と /reputation
```

上記は `https://graph.microsoft.com/v1.0/security/threatIntelligence` 配下。
正引き/逆引きはMicrosoftの記録済みデータであり、実装から対象へライブDNS問い合わせする意味ではない。
証明書一覧のhostSslCertificateは観測関係を表し、別にsslCertificateを関連づける。

- [Host](https://learn.microsoft.com/en-us/graph/api/resources/security-host?view=graph-rest-1.0)
- [passiveDns](https://learn.microsoft.com/en-us/graph/api/security-host-list-passivedns?view=graph-rest-1.0)
- [passiveDnsReverse](https://learn.microsoft.com/en-us/graph/api/security-host-list-passivednsreverse?view=graph-rest-1.0)
- [Host certificates](https://learn.microsoft.com/en-us/graph/api/security-host-list-sslcertificates?view=graph-rest-1.0)
- [hostSslCertificate model](https://learn.microsoft.com/en-us/graph/api/resources/security-hostsslcertificate?view=graph-rest-1.0)
- [Certificate detail](https://learn.microsoft.com/en-us/graph/api/security-sslcertificate-get?view=graph-rest-1.0)
- [Certificate relatedHosts](https://learn.microsoft.com/en-us/graph/api/security-sslcertificate-list-relatedhosts?view=graph-rest-1.0)

## 認証・権利

Application permissionは `ThreatIntelligence.Read.All`。Graph tokenはMSAL client credentialsで取得する。
テナント識別子はこの認証/権利確認に必要だが、自社テレメトリの検索には利用しない。

[現行overview](https://learn.microsoft.com/en-us/graph/api/resources/security-threatintelligence-overview?view=graph-rest-1.0)はDefender XDR/Sentinel顧客に別APIライセンス不要と記載。
個別の古いAPIページには旧Portal/API add-on要件が残る。対象tenantとendpointで実際に確認するまで成功としない。
Entra app作成・管理者同意・APIアクセス・データのAI処理方針は、利用者環境で確認する必要がある。

## 公開ソフトウェアの流用

```text
MCP Python SDK 1.30.0   MCP framing、initialize、tools/list/call、stdio、構造化出力
Microsoft MSAL 1.34.0   Entra client credentials、メモリtoken cache/更新
HTTPX 0.28.1           Graph通信、HTTP timeout、proxy/TLS、テスト用MockTransport
keyring 25.7.0         Windows WinVaultによる資格情報保存
Pydantic / idna        入出力schemaとIDNA検証
```

- [公式MCP SDK / v1.x](https://github.com/modelcontextprotocol/python-sdk/tree/v1.x)
- [MCP 1.30.0](https://pypi.org/project/mcp/1.30.0/)（v1は保守ライン、v2へ無検証で自動更新しない）
- [MSAL](https://github.com/AzureAD/microsoft-authentication-library-for-python)
- [MSAL client credentials](https://learn.microsoft.com/en-us/entra/msal/python/advanced/client-credentials)
- [HTTPX](https://github.com/encode/httpx)
- [keyring](https://github.com/jaraco/keyring)

これらを依存として利用し、独自のMCP/OAuthプロトコルを再実装しない。配布パッケージの上流ライセンスを保持する。
公開コミュニティ [microsoft-defender-mcp](https://github.com/bitbytelabio/microsoft-defender-mcp) は初期API利用例の参考。
広いDefender管理機能やRustサーバー全体は取り込まず、コードの直接転載も行っていない。
既存VT-MCPはTunnelの接続方式・資格情報分離の参考にしただけで、インストールを変更しない。

[OpenAI Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels) を既存VTと同様の接続方式として利用する。
MDTIは別profile/別tunnel IDにし、各MCPプロセスは別venvの実行ファイルを直接起動する。
Microsoft公式Sentinel MCPは不要で、本実装に依存しない。自社ログ探索もSecurity Copilot Entity Analyzerも取り込まない。
