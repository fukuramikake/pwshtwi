pwshtwi
=======
# これは何
Windows PowerShell でこっそりTwitterのタイムラインを見るためのスクリプトです。
が、Twitterのディスプレイガイドラインにはまったく準拠していない（てか無理）ので、
TwitterクライアントではなくTwitterのAPI動作確認ツールぐらいに考えていただけると。
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
たぶん、スクリプトの実行の許可を一度設定する必要があります。あと.NET Framework 4.5が必要。
なので、WindowsXPのようなレガシーOSでは動きません。Windows 7のようなデフォのPowerShellのCLRバージョンが2.0なPowerShellでも動かないので、最新のPowerShellを入れると良いです。
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

## show
showコマンドを入力すると、statuses/show/:id RestAPIをコールして、指定のつぶやきを表示します。
in_reply_to_status_idがある場合は、繰り返しで読み込んで表示します（会話を表示）
### option
id以外にも対応しているつもりだけどたぶん動かない。

例) Input command.:show id:123456789012345678

## usertl
usertlコマンドを入力すると、statuses/user_timeline RestAPIをコールして、指定のユーザのつぶやきを表示します。

### option
screen_nameに対応。他はテストしてません。

例) Input command.:usertl screen_name:fukuramikake
@は要らないです。ついてても動くみたいですが。

### rtsofme
rtsofmeコマンドを入力すると、statuses/reteweet_of_me RestAPIをコールして、リツイートされた自分のつぶやきを表示します。
あまり使えません。

### rts
rtsコマンドを入力すると、statuses/retweets/:id RestAPIをコールして、指定のつぶやきをリツイートした人を表示します。

例) Input command.:rts id:123456789012345678

### favs
favsコマンドを入力すると、favofites/list RestAPIをコールして、指定のユーザのFavoritesを表示します。

例) Input command.:favs screen_name:fukuramikake

何も指定しないと、自分のFavoritesが表示されます。
Favoritesされた自分のつぶやきが表示される機能ではありません。

### unfav
unfavコマンドを入力すると、favorites/destroy RestAPIをコールして、自分の特定のFavoritesを取り消します。

例) Input command.:unfav id:123456789012345678

### destroy
destroyコマンドを入力すると、statuses/destroy/:id RestAPIをコールし、自分の特定のつぶやきを削除します。

例) destroy id:123456789012345678

本来はこのコマンドでReTweetも解除できるはずですが、ReTweet Idの取得が面倒なので出来ないです。

# Proxyについて
GetSystemWebProxy()でプロキシが取得できたっぽいときはプロキシを使います。
インターネットオプション > 接続 > LANの設定 から設定するプロキシがこれにあたります。
認証が必要っぽいときは認証ダイアログを出します。

# 既知の不具合
* 結構潜んでそう


# ToDo
* タイムラインをもうちょい見やすく(URLの展開とかまったくしてない)
* ユーザー情報を表示できるように(要る?)
* エラートラップが雑
* RTの取り消しをできるようにしたい

# 他
そのうちやる。
