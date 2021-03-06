function Invoke-RemoveCertificates([string] $issuedBy)
{
	$certs = Get-ChildItem cert:\CurrentUser\My | where { $_.Issuer -match $issuedBy }
	if($certs)
	{
		foreach ($cert in $certs) 
		{
			$store = Get-Item $cert.PSParentPath
			$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::MaxAllowed)
			$store.Remove($cert)
			$store.Close()
		}
	}
	#Remove Any Trusted Root Certificates
	$certs = Get-ChildItem cert:\CurrentUser\Root | where { $_.Issuer -match $issuedBy }
	if($certs)
	{
	foreach ($cert in $certs) 
		{
			$store = Get-Item $cert.PSParentPath
			$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::MaxAllowed)
			$store.Remove($cert)
			$store.Close()
		}
	}
	[Console]::WriteLine("Certificates Removed")
		
}

function Invoke-CreateCACertificate([string] $certSubject)
{
    
  
    $cert = New-SelfSignedCertificate -certstorelocation cert:\CurrentUser\My -DnsName $certSubject -Type Custom -KeyAlgorithm RSA  -KeyUsage CertSign,CRLSign

    #Copy Into Root Store
     
    $DestStoreScope = 'CurrentUser'
    $DestStoreName = 'root'
 
    $DestStore = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store -ArgumentList $DestStoreName, $DestStoreScope
    $DestStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $DestStore.Add($cert)
    $DestStore.Close()

    return $cert

  
     
}

function Invoke-CreateCertificate([string] $certSubject)
{
    # Put the Cert in a global variable to reduce lookups.
    #$selfsignCA = Get-ChildItem cert:\CurrentUser\My| Where-Object { $_.Subject -match "__Interceptor_Trusted_Root" }
    $cert = New-SelfSignedCertificate -certstorelocation cert:\CurrentUser\My -Subject $certSubject -DnsName $certSubject -Signer $selfsignCA -Type Custom  `
    -KeyAlgorithm ECDSA_nistP256 -CurveExport CurveName 
    return $cert
     
}

function Receive-ServerHttpResponse ([System.Net.WebResponse] $response)
{
	#Returns a Byte[] from HTTPWebRequest, also for HttpWebRequest Exception Handling
	Try
	{
		[string]$rawProtocolVersion = "HTTP/" + $response.ProtocolVersion
		[int]$rawStatusCode = [int]$response.StatusCode
		[string]$rawStatusDescription = [string]$response.StatusDescription
		$rawHeadersString = New-Object System.Text.StringBuilder 
		$rawHeaderCollection = $response.Headers
		$rawHeaders = $response.Headers.AllKeys
		[bool] $transferEncoding = $false 
		# This is used for Chunked Processing.
		
		foreach($s in $rawHeaders) {
			#We'll handle setting cookies later
			if($s -eq "Set-Cookie") { Continue }
			if($s -eq "Transfer-Encoding")  {
				$transferEncoding = $true
				continue
			}
			[void]$rawHeadersString.AppendLine($s + ": " + $rawHeaderCollection.Get($s) ) 
		}	
		$setCookieString = $rawHeaderCollection.Get("Set-Cookie") -Split '($|,(?! ))'
		if($setCookieString) {
			foreach ($respCookie in $setCookieString) {
				if($respCookie -eq "," -Or $respCookie -eq "") {continue}
				[void]$rawHeadersString.AppendLine("Set-Cookie: " + $respCookie) 
			}
		}
		
		$responseStream = $response.GetResponseStream()
		
		$rstring = $rawProtocolVersion + " " + $rawStatusCode + " " + $rawStatusDescription + "`r`n" + $rawHeadersString.ToString() + "`r`n"
		
		[byte[]] $rawHeaderBytes = [System.Text.Encoding]::Ascii.GetBytes($rstring)
        Write-Host $rstring -Fore Green
        $stream.Write( $rstring + "`r`n`r`n") 
		
		[void][byte[]] $outdata 
		$tempMemStream = New-Object System.IO.MemoryStream
		[byte[]] $respbuffer = New-Object Byte[] 32768
		
		if($transferEncoding)
		{
			$reader = New-Object System.IO.StreamReader($responseStream)
			[string] $responseFromServer = $reader.ReadToEnd()
			            
			$outdata = [System.Text.Encoding]::UTF8.GetBytes($responseFromServer)
			$reader.Close()
		}
		else
		{
			while($true)
			{
				[int] $read = $responseStream.Read($respbuffer, 0, $respbuffer.Length)
				if($read -le 0)
				{
					$outdata = $tempMemStream.ToArray()
					break
				}
				$tempMemStream.Write($respbuffer, 0, $read)
			}
		
		}

		[byte[]] $rv = New-Object Byte[] ($rawHeaderBytes.Length + $outdata.Length)
		
		[System.Buffer]::BlockCopy( $rawHeaderBytes, 0, $rv, 0, $rawHeaderBytes.Length)
		[System.Buffer]::BlockCopy( $outdata, 0, $rv, $rawHeaderBytes.Length, $outdata.Length ) 
	    
		
		$tempMemStream.Close()
		$response.Close()
                    
		return $rv
	}
	Catch [System.Exception]  {
		[Console]::WriteLine("Get Response Error")
		[Console]::WriteLine($_.Exception.Message)
    }
	
            }

function Send-ServerHttpRequest([string] $URI, [string] $httpMethod,[byte[]] $requestBytes, [System.Net.WebProxy] $proxy )
{	
	#Prepare and Send an HttpWebRequest From Byte[] Returns Byte[]
	Try
	{
		$requestParse = [System.Text.Encoding]::UTF8.GetString($requestBytes)
		[string[]] $requestString = ($requestParse -split '[\r\n]') |? {$_} 
		
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
		[System.Net.HttpWebRequest] $request = [System.Net.HttpWebRequest] [System.Net.WebRequest]::Create($URI)	
		
		$request.KeepAlive = $false
		$request.ProtocolVersion = [System.Net.Httpversion]::version11 
		$request.ServicePoint.ConnectionLimit = 1
		if($proxy -eq $null) { $request.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy() }
		else { $request.Proxy = $proxy }
		$request.Method = $httpMethod
		$request.AllowAutoRedirect = $true 
		$request.AutomaticDecompression = [System.Net.DecompressionMethods]::None
	
		For ($i = 1; $i -le $requestString.Length; $i++) {
			$line = $requestString[$i] -split ": " 
			if ( $line[0] -eq "Host" -Or $line[0] -eq $null ) { continue }
			Try
			{
				#Add Header Properties Defined By Class
				switch($line[0])
				{
					"Accept" { $request.Accept = $line[1] }
					"Connection" { "" }
					"Content-Length" { $request.ContentLength = $line[1] }
					"Content-Type" { $request.ContentType = $line[1] }
					"Expect" { $request.Expect = $line[1] }
					"Date" { $request.Date = $line[1] }
					"If-Modified-Since" { $request.IfModifiedSince = $line[1] }
					"Range" { $request.Range = $line[1] }
					"Referer" { $request.Referer = $line[1] }
					"User-Agent" { $request.UserAgent = $line[1] } #You can Add Custom User_agent
					            
					"Transfer-Encoding"  { $request.TransferEncoding = $line[1] } 
					default { 
                        if($line[0] -eq "Accept-Encoding") {	
						$request.Headers.Add( $line[0], " ") #Take that Gzip...
							#Otherwise have to decompress response to tamper with content...
						}
						else {
							$request.Headers.Add( $line[0], $line[1])
						}	
	
					}
				}
				
			}
			Catch {}
		}
			
		if (($httpMethod -eq "POST") -And ($request.ContentLength -gt 0))  {
			[System.IO.Stream] $outputStream = [System.IO.Stream]$request.GetRequestStream()
			$outputStream.Write($requestBytes, $requestBytes.Length - $request.ContentLength, $request.ContentLength)
			$outputStream.Close()
		}
		
		
		return Receive-ServerHttpResponse $request.GetResponse()
		
	}
	Catch [System.Net.WebException] {
		#HTTPWebRequest  Throws exceptions based on Server Response.  So catch and return server response
		if ($_.Exception.Response) {
			return Receive-ServerHttpResponse $_.Exception.Response
        }
			
    }
	Catch [System.Exception] {	
		Write-Verbose $_.Exception.Message
	}
	
}

function Receive-ClientHttpRequest([System.Net.Sockets.TcpClient] $client, [System.Net.WebProxy] $proxy)
{
	
	Try
	{	
		$clientStream = $client.GetStream()
		$byteArray = new-object System.Byte[] 32768 
		[void][byte[]] $byteClientRequest

		do {
		[int] $NumBytesRead = $clientStream.Read($byteArray, 0, $byteArray.Length) 
		$byteClientRequest += $byteArray[0..($NumBytesRead - 1)]  
		 
		} While ($clientStream.DataAvailable -And $NumBytesRead -gt 0) 
		
		$requestString = [System.Text.Encoding]::UTF8.GetString($byteClientRequest)
        
		[string[]] $requestArray = ($requestString -split '[\r\n]') |? {$_} 
		[string[]] $methodParse = $requestArray[0] -split " "
		 
		if($methodParse[0] -ceq "CONNECT") {
                        

		[string[]] $domainParse = $methodParse[1].Split(":")
			            
		$connectSpoof = [System.Text.Encoding]::Ascii.GetBytes("HTTP/1.1 200 Connection Established`r`nTimeStamp: " + `
        [System.DateTime]::Now.ToString() + "`r`n`r`n")
		$clientStream.Write($connectSpoof, 0, $connectSpoof.Length)	
		$clientStream.Flush()
		$sslStream = New-Object System.Net.Security.SslStream($clientStream , $false)
		$sslStream.ReadTimeout = 500
		$sslStream.WriteTimeout = 500
		$sslcertfake = (Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -eq "CN=" + $domainParse[0] })
			            
                        
		if ($sslcertfake -eq $null)
		{
				           
            $sslcertfake =  Invoke-CreateCertificate $domainParse[0] 
		}
			            
		$sslStream.AuthenticateAsServer($sslcertfake, $false, [System.Security.Authentication.SslProtocols]::None, $false)
		Write-Host $sslStream.SslProtocol -Fore White
		$sslbyteArray = new-object System.Byte[] 32768
		[void][byte[]] $sslbyteClientRequest
			
	    Do  {
		[int] $NumBytesRead = $sslStream.Read($sslbyteArray, 0, $sslbyteArray.Length) 
		$sslbyteClientRequest += $sslbyteArray[0..($NumBytesRead - 1)]  
		} While ( $clientStream.DataAvailable  )
			
		$SSLRequest = [System.Text.Encoding]::UTF8.GetString($sslbyteClientRequest)
			            
        Write-Host $SSLRequest -Fore Yellow
        $stream.Write($SSLRequest)
			
		[string[]] $SSLrequestArray = ($SSLRequest -split '[\r\n]') |? {$_} 
		[string[]] $SSLmethodParse = $SSLrequestArray[0] -split " "
			
		$secureURI = 'https://' + $domainParse[0] + $SSLmethodParse[1]
			            

		[byte[]] $byteResponse =  Send-ServerHttpRequest $secureURI $SSLmethodParse[0] $sslbyteClientRequest $proxy
        $sslStream.Write($byteResponse, 0, $byteResponse.Length )                   
                       
		}
		Else {
			[byte[]] $proxiedResponse = Send-ServerHttpRequest $methodParse[1] $methodParse[0] $byteClientRequest $proxy
			$clientStream.Write($proxiedResponse, 0, $proxiedResponse.Length)
		}
		            
		$stream.FlushAsync() |Out-Null
	}
	Catch {
		Write-Verbose $_.Exception.Message
		            
	}
	            
    $client.Close()
}



function Main()
{	
	Invoke-RemoveCertificates "__Interceptor_Trusted_Root" # Call to Clean Up Previous Certificates Installed.
    Invoke-CreateCACertificate "__Interceptor_Trusted_Root" # Install Your Local CA - These are hardcoded , You could easily replace
    $selfsignCA = Get-ChildItem cert:\CurrentUser\My| Where-Object { $_.Subject -match "__Interceptor_Trusted_Root" } 
    #"Cache" selfsignCA to prevent all the lookups.
	
	if($ListenPort)
	{
		 $port = $ListenPort
	}
	else
	{
		$port = 8888
	}
	
	$endpoint = New-Object System.Net.IPEndPoint ([system.net.ipaddress]::any, $port)
	$listener = New-Object System.Net.Sockets.TcpListener $endpoint
	
		
	
	$listener.Start()
	[Console]::WriteLine("Listening on $port")
	$client = New-Object System.Net.Sockets.TcpClient
	$client.NoDelay = $true
	

    $selfsignCA = Get-ChildItem cert:\CurrentUser\My| Where-Object { $_.Subject -match "__Interceptor_Trusted_Root" }

	while($true)  {
		 if ($listener.Pending()) {
            $client = $listener.AcceptTcpClient()
            Receive-ClientHttpRequest $client $proxy
            continue;
            }
            start-sleep -Milliseconds 1000  
            $stream.FlushAsync() | Out-Null 	
		
	}
	

}

 
$path = 'Interceptor_Log_'+[DateTimeOffset]::Now.ToUnixTimeSeconds()+'_.txt'
$stream = [System.IO.StreamWriter]::new($path)

$stream.Write('Log File ' + [System.DateTime]::Now.ToString() + "`r`n")

# Sample Test  
# curl -k -tlsv1.3 -v -x localhost:8888 https://www.example.com


Main

$stream.close()
Exit
