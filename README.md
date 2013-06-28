pwshtwi
=======
# これは何
Windows PowerShell でこっそりTwitterのタイムラインを見るためのスクリプトです。
# 使い方
## Twitter の consumer 登録
Consumer secretの隠し方がわからなかったので思い切ってself-serviceにしました。
Twitterの開発者向けページで登録して、consumer keyとconsumer secretを発番しておいてください。
→ https://dev.twitter.com/apps
## Consumer key、Consumer secretの記入
スクリプトの最後の方にconsumer keyとconsumer secretを書くところがあるので、
そこに発番された文字列を記入してください。見ればわかる。
## 動かし方
Windows PowerShell を立ち上げ、スクリプトを実行してください。
動かない? ググれ。
# 認証
スクリプトを実行すると、Twitterの連携認証ページが開くので、認証したらpinを入力してください。
（スクリプトが入力待ち状態になってます）
# コマンド
認証完了すると、コマンド待ち受け状態になるので、APIを呼び出すコマンドを入力してください。
## home
homeコマンドを入力すると、statuses/home_timeline RestAPIをコールして、取得結果を適当に表示します。
### option
countとsince_idとmax_idに対応。trim_userとexclude_repliesも書いてあるけど動くかどうかは確認してない。

例) Input command.:home count:100 max_id:123456789012345678

123456789012345678までのタイムラインを100件拾う。昔に向かって100件です。過去ログみたいときにどうぞ。

古いのを見たくない場合はsince_idを指定してください。

idはPowerShell上でマウスで範囲選択して右クリックでコピー、右クリックで貼り付けできます。

## mentions
mentionsコマンドを入力すると、statuses/mentions_timeline RestAPIをコールして、取得結果を適当に表示します。
### option
countとsince_idとmax_idに対応。trim_userも書いてあるけど動くかどうかは確認してない。

例) Input command.:mentions

## update
updateコマンドを入力すると、statuses/update RestAPIをコールして、つぶやきを投稿します。
### option
statusとin_reply_to_status_idに対応。trim_userも書いてあるけど動くかどうかは確認してない。

例) Input command.:update status:これはテストです in_reply_to_status_id:123456789012345678

in_reply_to_status_idを指定すると、特定のtweetへのリプライとして送信することができます。

一応、statusにsplitされうる文字列が入っていた場合も、続きのコマンドでstatusやin_reply_to_status_idが現れるまでは、半角スペースで連結して投げてくれる（ハズ）です。

## rt
rtコマンドを入力すると、statuses/retweet/:id RestAPIをコールして、指定のつぶやきをRetweetします。
### option
idに対応。これは必須です。

例) Input command.:rt id:123456789012345678

## fav
favコマンドを入力すると、favorites/create RestAPIをコールして、指定のつぶやきをお気に入りにします。
### option
idに対応。これは必須です。

例) Input command.:fav id:123456789012345678

# 既知の不具合
* たぶん無い


# ToDo
* タイムラインをもうちょい見やすく
* ユーザー情報を表示できるように
* ほとんどエラートラップしてないですね
* idのコピペ大変なんだがどうにかならんかのー
* Enterで即Mention飛んでくのやめたい。キケン。

# 他
そのうちやる。
