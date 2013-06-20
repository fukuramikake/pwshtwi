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
        $signature = $Request.GetHMACSHA(
          $Request.GetSignKey(),
          $Request.GetSignatureBaseString("POST",$url,$auth)
          )
        $header = "OAuth "
        foreach($key in $auth.keys | sort){
            $value = $Request.UrlEncode($auth[$key])
            $header += $key + "=""" + $value + ""","
        }
        $header += "oauth_signature=""" + $signature + """"

        [System.Collections.Generic.List[System.Collections.Generic.KeyValuePair`2[System.String,System.String]]]$post = `
          New-Object 'System.Collections.Generic.List[System.Collections.Generic.KeyValuePair`2[System.String,System.String]]'
        foreach($key in $contents.keys | sort){
            $value = New-Object 'System.Collections.Generic.KeyValuePair`2[System.String,System.String]' `
            -ArgumentList @($key,$contents[$key])
            $post.Add($value)
        }

        $client = New-Object -TypeName System.Net.Http.HttpClient
        $client.DefaultRequestHeaders.Authorization = $header
        $httpContent = New-Object -TypeName System.Net.Http.FormUrlEncodedContent (,$post)
        $response = $client.PostAsync($url, $httpContent).Result
        return $response.Content.ReadAsStringAsync().Result
      } -PassThru `
    | Add-Member -MemberType ScriptMethod -Name GetRequest -Value{
        param($url, $auth, $contents)
        $query = ""
        if($contents.Count -gt 0){
            foreach($key in $contents.keys){
                $params += $Request.UrlEncode($key) + "=" + $Request.UrlEncode($contents[$key]) + "&"
            }
        }
        if($query.Length -gt 0)
        {
            $url += "?" + $query.Substring(0,$query.Length - 1)
        }
        
        $signature = $Request.GetHMACSHA(
          $Request.GetSignKey(),
          $Request.GetSignatureBaseString("GET",$url,$auth)
          )
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

function replaceSource($source){
    return [System.Text.RegularExpressions.Regex]::Match($source,"rel=""nofollow"">(?<str>.+)</a>").Groups["str"].Value;
}

$RestApi = {
	param($request, [string]$user_id, [string]$oauth_token, [string]$screen_name, [string]$oauth_token_secret)
	$MyInvocation.MyCommand.ScriptBlock `
	| Add-Member -MemberType NoteProperty -Name UserId     -Force -Value $user_id     -PassThru `
	| Add-Member -MemberType NoteProperty -Name OauthToken -Force -Value $oauth_token -PassThru `
	| Add-Member -MemberType NoteProperty -Name ScreenName -Force -Value $screen_name -PassThru `
    | Add-Member -MemberType ScriptMethod -Name HomeTL            -Value {
        $result = $request.GetRequest("https://api.twitter.com/1.1/statuses/home_timeline.json",
        @{
            "oauth_consumer_key" = $request.ConsumerKey;
            "oauth_nonce" = [System.Guid]::NewGuid().ToString();
            "oauth_signature_method" = "HMAC-SHA1";
            "oauth_token" = $RestApi.OAuthToken;
            "oauth_timestamp" = $request.GetTimeStamp();
            "oauth_version" = "1.0"
        }, @{})
        return $result
      } -PassThru
}

function Command($api){
    $command = Read-Host "Input command."

    switch($command.ToLower())
    {
        "home" {
            $tl = $api.HomeTL()
            $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
            $obj = $serializer.DeserializeObject($tl)


            for($i = $obj.Length - 1; $i -gt -1; $i--){
                $tweet = $obj[$i]
            <#
            foreach($tweet in $obj){#>
                if($tweet.Keys.Contains("retweeted_status")){
                    Write-Host($tweet["retweeted_status"]["user"]["name"] + " @" + $tweet["retweeted_status"]["user"]["screen_name"] `
                    + " ReTweeted by " + $tweet["user"]["name"] + " @" + $tweet["user"]["screen_name"]) -ForegroundColor Cyan
                    Write-Host($tweet["retweeted_status"]["text"]) -BackgroundColor DarkCyan
                    $source = replaceSource $tweet["retweeted_status"]["source"]
                    Write-Host($tweet["retweeted_status"]["created_at"] + " from " + $source) -ForegroundColor Gray
                }
                else{
                    Write-Host($tweet["user"]["name"] + " @" + $tweet["user"]["screen_name"]) -ForegroundColor Cyan
                    Write-Host($tweet["text"]) -BackgroundColor DarkBlue
                    $source = replaceSource $tweet["source"]
                    Write-Host($tweet["created_at"] + " from " + $source)  -ForegroundColor Gray
                }
                <#
            }
            #>
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





