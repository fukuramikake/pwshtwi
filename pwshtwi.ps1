[System.Reflection.Assembly]::LoadWithPartialName("System.Net.Http")
[System.Reflection.Assembly]::LoadWithPartialName("System.Web")
[System.Reflection.Assembly]::LoadWithPartialName("System.Security")
[System.Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions")

$Request = {
	param([string]$consumerKey, [string]$consumerSecret, [string]$requestTokenUrl, [string]$authorizeUrl, [string]$accessTokenUrl)
	$MyInvocation.MyCommand.ScriptBlock `
	| Add-Member -MemberType NoteProperty -Name ConsumerKey      -Force -Value $consumerKey     -PassThru `
	| Add-Member -MemberType NoteProperty -Name ConsumerSecret   -Force -Value $consumerSecret  -PassThru `
	| Add-Member -MemberType NoteProperty -Name RequestTokenUrl  -Force -Value $requestTokenUrl -PassThru `
	| Add-Member -MemberType NoteProperty -Name AuthorizeUrl     -Force -Value $authorizeUrl    -PassThru `
	| Add-Member -MemberType NoteProperty -Name AccessTokenUrl   -Force -Value $accessTokenUrl  -PassThru `
    | Add-Member -MemberType NoteProperty -Name OauthTokenSecret -Force -Value ""               -PassThru `
    | Add-Member -MemberType ScriptMethod -Name GetTimeStamp            -Value {
        return [int][double]::Parse($(Get-Date -date (Get-Date).ToUniversalTime()-uformat %s))
      } -PassThru `
    | Add-Member -MemberType ScriptMethod -Name UrlEncode -Value {
        param([string]$str)
        $unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($str)
        [string]$encoded = ""
        foreach($byte in $bytes){
          if($unreserved.IndexOf([char]$byte) -ne -1){
            $encoded += [char]$byte
          }
          else{
            $encoded += [System.String]::Format("%{0:X2}", $byte)
          }
        }
      return $encoded
      } -PassThru `
    | Add-Member -MemberType ScriptMethod -Name GetSignKey -Value {
        param()
        return $Request.UrlEncode($Request.ConsumerSecret) + "&" + $Request.UrlEncode($Request.OauthTokenSecret)
      } -PassThru `
    | Add-Member -MemberType ScriptMethod -Name GetSignatureBaseString -Value{
        param($httpMethod, $url, $hashtable)
        [string]$str += $Request.UrlEncode($httpMethod) + "&" + $Request.UrlEncode($url)
        [string]$c = ""
        foreach($key in $hashtable.keys | sort ){
          $c += $key + "=" + $hashtable[$key] + "&"
        }
        $c = $c.Substring(0,$c.Length - 1)
        [string]$encoded = $Request.UrlEncode($c)
        $str += "&" + $encoded
        return $str
      } -PassThru `
    | Add-Member -MemberType ScriptMethod -Name GetHMACSHA -Value{
        param($signKey,$signatureBaseString)
        $hmacsha = New-Object System.Security.Cryptography.HMACSHA1
        $hmacsha.key = [Text.Encoding]::UTF8.GetBytes($signKey)
        $hash = $hmacsha.ComputeHash([Text.Encoding]::UTF8.GetBytes($signatureBaseString))
        $base64 = [System.Convert]::ToBase64String($hash)
        $signature = $Request.UrlEncode($base64)
        return $signature;
      } -PassThru `
    | Add-Member -MemberType ScriptMethod -Name PostRequest -Value{
        param($url, $auth, $contents)
        if($contents.Length -gt 0){
            foreach($key in $contents.keys){
                $auth[$key] = $Request.UrlEncode($contents[$key])
            }
        }
        $signature = $Request.GetHMACSHA(
          $Request.GetSignKey(),
          $Request.GetSignatureBaseString("POST",$url,$auth)
          )
        $header = "OAuth "
        foreach($key in $auth.keys | sort){
            if($key.StartsWith("oauth_")){
                $value = $Request.UrlEncode($auth[$key])
                $header += $key + "=""" + $value + ""","
            }
        }
        $header += "oauth_signature=""" + $signature + """"

        [string]$post = "";
        foreach($key in $contents.keys | sort){
            $post += $Request.UrlEncode($key) + "=" + $Request.UrlEncode($contents[$key]) + "&"
        }
        if($post -ne ""){
            $post = $post.Substring(0,$post.Length - 1)
        }

        $client = New-Object -TypeName System.Net.Http.HttpClient
        $client.DefaultRequestHeaders.Authorization = $header

        $httpContent = New-Object -TypeName System.Net.Http.StringContent($post, [System.Text.Encoding]::UTF8, "application/x-www-form-urlencoded")
        $response = $client.PostAsync($url, $httpContent).Result
        return $response.Content.ReadAsStringAsync().Result
      } -PassThru `
    | Add-Member -MemberType ScriptMethod -Name GetRequest -Value{
        param($url, $auth, $contents)
        $query = ""
        if($contents.Length -gt 0){
            foreach($key in $contents.keys){
                $query += $Request.UrlEncode($key) + "=" + $Request.UrlEncode($contents[$key]) + "&"
                $auth[$key] = $Request.UrlEncode($contents[$key])
            }
        }
        $signature = $Request.GetHMACSHA(
            $Request.GetSignKey(),
            $Request.GetSignatureBaseString("GET",$url,$auth)
        )
        if($query.Length -gt 0){
            $query = $query.Substring(0,$query.Length - 1)
            $url = $url + "?" + $query
        }
        $header = "OAuth "
        foreach($key in $auth.keys | sort){
            $value = $Request.UrlEncode($auth[$key])
            $header += $key + "=""" + $value + ""","
        }
        $header += "oauth_signature=""" + $signature + """"

        $client = New-Object -TypeName System.Net.Http.HttpClient
        $client.DefaultRequestHeaders.Authorization = $header
        $response = $client.GetAsync($url).Result
        return $response.Content.ReadAsStringAsync().Result
      } -PassThru 

}

function Login($request){

    <# Get Request Token #>
    $request.OauthTokenSecret = ""
    $result = $request.PostRequest($request.RequestTokenUrl,@{
            "oauth_consumer_key" = $request.ConsumerKey;
            "oauth_nonce" = [System.Guid]::NewGuid().ToString();
            "oauth_signature_method" = "HMAC-SHA1";
            "oauth_timestamp" = $request.GetTimeStamp();
            "oauth_version" = "1.0"
        }, @{})

    if( ($result -ne $null) -and ($result -ne "") ){
        $oauth_token = [System.Text.RegularExpressions.Regex]::Match($result,"oauth_token=(?<str>[0-9a-zA-Z]+)").Groups["str"].Value
        $oauth_token_secret = [System.Text.RegularExpressions.Regex]::Match($result,"oauth_token_secret=(?<str>[0-9a-zA-Z]+)").Groups["str"].Value
        $oauth_callback_confirmed = [System.Text.RegularExpressions.Regex]::Match($result,"oauth_callback_confirmed=(?<str>[0-9a-zA-Z]+)").Groups["str"].Value
        if($oauth_token -eq ""){
            Write-Host "request token fail."
            return
        }

        <# Input pin #>
        $url = $request.AuthorizeUrl + "?oauth_token=" + $oauth_token
        $ie = OpenInternetExplorer $url
        $pin = Read-Host "Input pin code."
        $ie.Quit()


        $request.OauthTokenSecret = $oauth_token_secret
        <# Get Access Token #>
        $result = $request.PostRequest($request.AccessTokenUrl,@{
            "oauth_consumer_key" = $request.ConsumerKey;
            "oauth_nonce" = [System.Guid]::NewGuid().ToString();
            "oauth_signature_method" = "HMAC-SHA1";
            "oauth_token" = $oauth_token;
            "oauth_verifier" = $pin;
            "oauth_timestamp" = $request.GetTimeStamp();
            "oauth_version" = "1.0"
        }, @{})

        if( ($result -ne $null) -and ($result -ne "") ){
            $authinfo = @{
                "oauth_token" = [System.Text.RegularExpressions.Regex]::Match($result,"oauth_token=(?<str>[0-9a-zA-Z_\\-]+)").Groups["str"].Value;
                "oauth_token_secret" = [System.Text.RegularExpressions.Regex]::Match($result,"oauth_token_secret=(?<str>[0-9a-zA-Z]+)").Groups["str"].Value;
                "user_id" = [System.Text.RegularExpressions.Regex]::Match($result,"user_id=(?<str>[0-9]+)").Groups["str"].Value;
                "screen_name" = [System.Text.RegularExpressions.Regex]::Match($result,"user_id=(?<str>[0-9a-zA-Z_]+)").Groups["str"].Value
                }
            
            if($authinfo["oauth_token"] -eq ""){
                <# Retry #>
                Write-Host "access token fail."
                Login $request
            }
            else{
                <# Success #>
                $request.OauthTokenSecret = $authinfo["oauth_token_secret"]
                return $authinfo
            }

        }
        else{
            <# Retry #>
            Login($request)
        }

    }
    else{
        <# Retry #>
        Login($request)
    }
}

function OpenInternetExplorer($url){
    $ie = New-Object -ComObject InternetExplorer.Application
    $ie.Visible = $true
    $ie.Navigate($url)
    return $ie
}

function ReplaceSource($source){
    return [System.Text.RegularExpressions.Regex]::Match($source,"rel=""nofollow"">(?<str>.+)</a>").Groups["str"].Value;
}

function ConvertTimeZone($twitterDate){
    return [string][System.DateTimeOffset]::ParseExact($twitterDate, "ddd MMM dd HH:mm:ss zzz yyyy", `
        [System.Globalization.CultureInfo]::InvariantCulture).LocalDateTime
    
}

$RestApi = {
	param($request, [string]$user_id, [string]$oauth_token, [string]$screen_name, [string]$oauth_token_secret)
	$MyInvocation.MyCommand.ScriptBlock `
	| Add-Member -MemberType NoteProperty -Name UserId     -Force -Value $user_id     -PassThru `
	| Add-Member -MemberType NoteProperty -Name OauthToken -Force -Value $oauth_token -PassThru `
	| Add-Member -MemberType NoteProperty -Name ScreenName -Force -Value $screen_name -PassThru `
    | Add-Member -MemberType ScriptMethod -Name AuthParams        -Value {
        return @{
            "oauth_consumer_key" = $request.ConsumerKey;
            "oauth_nonce" = [System.Guid]::NewGuid().ToString();
            "oauth_signature_method" = "HMAC-SHA1";
            "oauth_token" = $RestApi.OAuthToken;
            "oauth_timestamp" = $request.GetTimeStamp();
            "oauth_version" = "1.0"
            }
      } -PassThru `
    | Add-Member -MemberType ScriptMethod -Name HomeTL            -Value {
        param($commands)
        $params = @{}
        if($commands.Length -gt 1){
            for($index = 1; $index -lt $commands.Length; $index++){
                $p = $commands[$index].Split(":", [StringSplitOptions]::RemoveEmptyEntries)
                if($p.Length -eq 2){
                    switch(([string]$p[0]).ToLower()){
                        "count" {
                            $i = $p[1] -as [Int32]
                            if($i -ge 1 -and $i -le 200){
                                $params["count"] = $i
                            }
                        }
                        "since_id" {
                            $i = $p[1] -as [Int64]
                            if($i){
                                $params["since_id"] = $i
                            }
                        }
                        "max_id" {
                            $i = $p[1] -as [Int64]
                            if($i){
                                $params["max_id"] = $i
                            }
                        }
                        "trim_user" {
                            if($p[1].ToLower() -eq "true" -or $p[1].ToLower() -eq "false"){
                                $params["trim_user"] = $p[1].ToLower()
                            }
                        }
                        "exclude_replies "{
                            if($p[1].ToLower() -eq "true" -or $p[1].ToLower() -eq "false"){
                                $params["exclude_replies "] = $p[1].ToLower()
                            }
                        }
                        default {
                            $params[[string]$p] = $p[1]
                        }
                    }
                }
            }
        }
        $result = $request.GetRequest("https://api.twitter.com/1.1/statuses/home_timeline.json",
        $RestApi.AuthParams(), $params)
        return $result
      } -PassThru `
    | Add-Member -MemberType ScriptMethod -Name Mentions          -Value {
        param($commands)
        $params = @{}
        if($commands.Length -gt 1){
            for($index = 1; $index -lt $commands.Length; $index++){
                $p = $commands[$index].Split(":", [StringSplitOptions]::RemoveEmptyEntries)
                if($p.Length -eq 2){
                    switch(([string]$p[0]).ToLower()){
                        "count" {
                            $i = $p[1] -as [Int32]
                            if($i -ge 1 -and $i -le 200){
                                $params["count"] = $i
                            }
                        }
                        "since_id" {
                            $i = $p[1] -as [Int64]
                            if($i){
                                $params["since_id"] = $i
                            }
                        }
                        "max_id" {
                            $i = $p[1] -as [Int64]
                            if($i){
                                $params["max_id"] = $i
                            }
                        }
                        "trim_user" {
                            if($p[1].ToLower() -eq "true" -or $p[1].ToLower() -eq "false"){
                                $params["trim_user"] = $p[1].ToLower()
                            }
                        }
                        default {
                            $params[[string]$p] = $p[1]
                        }
                    }
                }
            }
        }
        $result = $request.GetRequest("https://api.twitter.com/1.1/statuses/mentions_timeline.json",
        $RestApi.AuthParams(), $params)
        return $result
      } -PassThru `
    | Add-Member -MemberType ScriptMethod -Name Update -Value {
        param($commands)
        $params = @{}
        if($commands.Length -gt 1){
            for($index = 1; $index -lt $commands.Length; $index++){
                $p = $commands[$index].Split(":", [StringSplitOptions]::RemoveEmptyEntries)
                if($p.Length -eq 2){
                    switch(([string]$p[0]).ToLower()){
                        "status" {
                            $params["status"] = $p[1]
                            $ci = $index + 1
                            for($ci; $ci -lt $commands.Length; $ci++){
                                $tq = $commands[$ci].Split(":", [StringSplitOptions]::RemoveEmptyEntries)
                                $ignore = @("status","in_reply_to_status_id","lat","long","place_id","display_coordinates", "trim_user")
                                if( -not ($ignore -contains ([string]$tq[0]).ToLower()) ){
                                    $params["status"] += " " + $commands[$ci]
                                    $index++
                                }
                            }
                        }
                        "in_reply_to_status_id" {
                            $i = $p[1] -as [Int64]
                            if($i){
                                $params["in_reply_to_status_id"] = $i
                            }
                        }
                        "trim_user" {
                            if($p[1].ToLower() -eq "true" -or $p[1].ToLower() -eq "false"){
                                $params["trim_user"] = $p[1].ToLower()
                            }
                        }
                        default {
                            $params[[string]$p] = $p[1]
                        }
                    }
                }
            }
        }
        $result = $request.PostRequest("https://api.twitter.com/1.1/statuses/update.json",
        $RestApi.AuthParams(), $params)
        return $result

      } -PassThru `
    | Add-Member -MemberType ScriptMethod -Name Retweet -Value {
        param($commands)
        [Int64]$retweetId = $null
        if($commands.Length -gt 1){
            for($index = 1; $index -lt $commands.Length; $index++){
                $p = $commands[$index].Split(":", [StringSplitOptions]::RemoveEmptyEntries)
                if($p.Length -eq 2){
                    switch(([string]$p[0]).ToLower()){
                        "id" {
                            $i = $p[1] -as [Int64]
                            if($i){
                                $retweetId = $i
                            }
                        }
                    }
                }
            }
        }
        $result = $request.PostRequest("https://api.twitter.com/1.1/statuses/retweet/" + $retweetId + ".json",
        $RestApi.AuthParams(), @{})
        return $result
      } -PassThru `
    | Add-Member -MemberType ScriptMethod -Name Favorite -Value {
        param($commands)
        $params = @{}
        if($commands.Length -gt 1){
            for($index = 1; $index -lt $commands.Length; $index++){
                $p = $commands[$index].Split(":", [StringSplitOptions]::RemoveEmptyEntries)
                if($p.Length -eq 2){
                    switch(([string]$p[0]).ToLower()){
                        "id" {
                            $i = $p[1] -as [Int64]
                            if($i){
                                $params["id"] = $i
                            }
                        }
                    }
                }
            }
        }
        $result = $request.PostRequest("https://api.twitter.com/1.1/favorites/create.json",
        $RestApi.AuthParams(), $params)
        return $result
      } -PassThru
}

function Command($api){
    $command = Read-Host "Input command."
    $commands = -split $command

    switch($commands[0].ToLower())
    {
        "home" {
            $tl = $api.HomeTL($commands)
            $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
            $obj = $serializer.DeserializeObject($tl)

            if($obj["errors"].Length -gt 0){
                foreach($error in $obj["errors"]){
                    Write-Host $error["message"]
                }
            }
            else{
                for($i = $obj.Length - 1; $i -gt -1; $i--){
                    $tweet = $obj[$i]
                <#
                foreach($tweet in $obj){#>
                    if($tweet.Keys.Contains("retweeted_status")){
                        Write-Host($tweet["retweeted_status"]["user"]["name"] + " @" + $tweet["retweeted_status"]["user"]["screen_name"] `
                        + " ReTweeted by " + $tweet["user"]["name"] + " @" + $tweet["user"]["screen_name"]) -ForegroundColor Cyan
                        Write-Host($tweet["retweeted_status"]["text"]) -BackgroundColor DarkCyan
                        $source = ReplaceSource $tweet["retweeted_status"]["source"]
                        $dt = ConvertTimeZone $tweet["retweeted_status"]["created_at"]
                        Write-Host($dt + " from " + $source + `
                                   " id:" + $tweet["retweeted_status"]["id"]) -ForegroundColor Gray
                    }
                    else{
                        Write-Host($tweet["user"]["name"] + " @" + $tweet["user"]["screen_name"]) -ForegroundColor Cyan
                        Write-Host($tweet["text"]) -BackgroundColor DarkBlue
                        $source = ReplaceSource $tweet["source"]
                        $dt = ConvertTimeZone $tweet["created_at"]
                        Write-Host($dt + " from " + $source + " id:" + $tweet["id"])  -ForegroundColor Gray
                    }
                    <#
                }
                #>
                }
            }
        }
        "mentions" {
            $tl = $api.Mentions($commands)
            $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
            $obj = $serializer.DeserializeObject($tl)

            if($obj["errors"].Length -gt 0){
                foreach($error in $obj["errors"]){
                    Write-Host $error["message"]
                }
            }
            else{
                for($i = $obj.Length - 1; $i -gt -1; $i--){
                    $tweet = $obj[$i]
                <#
                foreach($tweet in $obj){#>
                    Write-Host($tweet["user"]["name"] + " @" + $tweet["user"]["screen_name"]) -ForegroundColor Cyan
                    Write-Host($tweet["text"]) -BackgroundColor DarkBlue
                    $source = ReplaceSource $tweet["source"]
                    $dt = ConvertTimeZone $tweet["created_at"]
                    Write-Host($dt + " from " + $source + " id:" + $tweet["id"])  -ForegroundColor Gray
                    <#
                }
                #>
                }
            }
        }
        "update" {
            $tl = $api.Update($commands)
            $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
            $obj = $serializer.DeserializeObject($tl)

            if($obj["errors"].Length -gt 0){
                foreach($error in $obj["errors"]){
                    Write-Host $error["message"]
                }
            }
            else{
                echo $obj["text"]
            }
        }
        "rt" {
            $tl = $api.Retweet($commands)
            $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
            $obj = $serializer.DeserializeObject($tl)

            if($obj["errors"].Length -gt 0){
                foreach($error in $obj["errors"]){
                    Write-Host $error["message"]
                }
            }
            else{
                echo $obj["retweeted_status"]["text"]
            }
        }
        "fav" {
            $tl = $api.Favorite($commands)
            $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
            $obj = $serializer.DeserializeObject($tl)

            if($obj["errors"].Length -gt 0){
                foreach($error in $obj["errors"]){
                    Write-Host $error["message"]
                }
            }
            else{
                echo $obj["text"]
            }
        }
        default{
            Write-Host "input valid command. ex) > home"
        }
    }
    Command $api



}


<# Enter your developer setting  #>
$req = &$Request "{Consumer key}" "{Consumer secret}" `
                 "https://api.twitter.com/oauth/request_token" `
                 "https://api.twitter.com/oauth/authorize" `
                 "https://api.twitter.com/oauth/access_token"

$authinfo = Login $req
$rest = &$RestApi $req $authinfo["user_id"] $authinfo["oauth_token"] $authinfo["screen_name"] $authinfo["oauth_token_secret"]

Command $rest





