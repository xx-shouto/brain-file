# Brain File

**Brain File** は、P2Pファイル共有を安全に行うためのPythonベースのアプリケーションです。  
検索・匿名ダウンロード・ピアキャッシュ管理などの機能を備えています。

---

## ⚠️ 注意

- VPN経由での使用を推奨します。直接インターネットに接続したまま起動すると危険です。
- 本ソフトは教育・研究目的で提供されており、違法ファイルの共有は禁止されています。

---

## 特徴

- AES-CTR 暗号化による通信
- DH鍵交換によるセッションキー生成
- ローカル・ピア検索対応
- ファイルタイプ・拡張子による検索フィルタ
- 自動リレー経由の匿名ダウンロード
- ピアキャッシュ管理
- `config.json` からの設定読み込み

---

## ライセンス

このプロジェクトは **Apache License 2.0** に基づいて公開されています。

```

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

````

---

## セットアップ方法

1. Python 3.12 以上をインストール
2. 仮想環境の作成（任意）

```bash
python -m venv venv
source venv/bin/activate  # macOS/Linux
venv\Scripts\activate     # Windows
````

3. 必要ライブラリのインストール

```bash
pip install cryptography
```

4. プロジェクトディレクトリに `config.json` を作成（任意）

```json
{
  "port": 8468,
  "files_dir": "shared_files",
  "download_dir": "downloads",
  "cache_file": "peer_cache.json"
}
```

5. 共有用フォルダを作成（`files_dir` に合わせて）

```bash
mkdir shared_files
mkdir downloads
```

---

## 起動方法

```bash
python main.py
```

起動時に以下の情報が表示されます：

* Node ID
* ローカルIP
* 使用ポート
* 利用可能なコマンド一覧

---

## コマンド一覧

| コマンド                                         | 説明                    |
| -------------------------------------------- | --------------------- |
| `/s <keyword> [ext:<ext>] [type:<filetype>]` | ファイル検索（キーワード＋オプション）   |
| `/g <sha1>`                                  | SHA1ハッシュを指定して匿名ダウンロード |
| `/cache`                                     | 現在のピアキャッシュ表示          |
| `/help`                                      | コマンド一覧表示              |
| `/exit`                                      | プログラム終了               |

### 検索オプション例

* `ext:txt` : 拡張子指定
* `type:image` : 画像ファイルのみ
* `type:video` : 動画ファイルのみ
* `type:audio` : 音声ファイルのみ
* `type:document` : 文書ファイル（txt, pdf, doc 等）

---

## ファイルダウンロード例

1. 検索でファイルの SHA1 を確認：

```text
> /s example
Found:
 - example.txt SHA1=abcd1234 relay_nodes=[...]
```

2. ダウンロード：

```text
> /g abcd1234
example.txt downloaded to downloads/abcd1234_example.txt
```

---

## 開発者向け

* ソースコードは `main.py` に全て含まれています。
* `config.json` でポートや共有フォルダを柔軟に変更可能。
* 追加機能としてファイルタイプ判定や非同期通信を拡張可能。

---

## 注意事項

* 不特定多数とファイルを共有するため、個人情報や機密情報を含むファイルは絶対に置かないでください。
* 違法コンテンツの共有は禁止されています。

