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
もっと前を見る、みたいな便利なコマンドはまだ無い。
# ToDo
* 表示するタイムラインの件数を指定できるようにする(count)
* もっと前を見れるようにする(max_idを使えばいける…か?)
* @を見れるようにする(statuses/mentions_timeline)
* @を送れるようにする(statuses/update) けど、in_reply_to_status_idはどうやって指定するようにするか…

# 他
そのうちやる。
