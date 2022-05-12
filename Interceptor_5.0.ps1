function Start-CertificateAuthority()
{
	#Thanks to @obscuresec for this Web Host
	#Pulls CA Certificate from Store and Writes Directly back to Mobile Device
	# example: http://localhost:8082/i.cer
	Start-Job -ScriptBlock {
			
			$Hso = New-Object Net.HttpListener
			$Hso.Prefixes.Add("http://+:8082/")
			$Hso.Start()
			While ($Hso.IsListening) {
				$HC = $Hso.GetContext()
				$HRes = $HC.Response
				$HRes.Headers.Add("Content-Type","text/plain")
				$cert = Get-ChildItem cert:\LocalMachine\Root | where { $_.Issuer -like "CN=__Interceptor_Trusted_Root" }
				$type = [System.Security.Cryptography.X509Certificates.X509ContentType]::cert
				$Buf = $cert.Export($type)
				$HRes.OutputStream.Write($Buf,0,$Buf.Length)
				$HRes.Close()
			}
				
			}
	
	
	
}

function Invoke-RemoveCertificates([string] $issuedBy)
{
	$certs = Get-ChildItem cert:\LocalMachine\My | where { $_.Issuer -match $issuedBy }
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
	$certs = Get-ChildItem cert:\LocalMachine\Root | where { $_.Issuer -match $issuedBy }
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
    
  
    $cert = New-SelfSignedCertificate -certstorelocation cert:\LocalMachine\My -DnsName $certSubject -Type Custom -KeyAlgorithm RSA  -KeyUsage CertSign,CRLSign


    #Copy Into Root Store
     
    $DestStoreScope = 'LocalMachine'
    $DestStoreName = 'root'
 
    $DestStore = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store -ArgumentList $DestStoreName, $DestStoreScope
    $DestStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $DestStore.Add($cert)
    $DestStore.Close()

    return $cert

  
     
}





$Global:Listener = [HashTable]::Synchronized(@{})
$Global:CnQueue = [System.Collections.Queue]::Synchronized((New-Object System.collections.queue))
$Global:space = [RunSpaceFactory]::CreateRunspace()
$space.Open()
$space.SessionStateProxy.setVariable("CnQueue", $CnQueue)
$space.SessionStateProxy.setVariable("Listener", $Listener)
$Global:newPowerShell = [PowerShell]::Create()
$newPowerShell.Runspace = $space
$Timer = New-Object Timers.Timer
$Timer.Enabled = $true
$Timer.Interval = 1000

Register-ObjectEvent -SourceIdentifier MonitorClientConnection -InputObject $Timer -EventName Elapsed -Action {
    While($CnQueue.count -ne 0) {
        $client = $CnQueue.Dequeue()
        $newRunspace = [RunSpaceFactory]::CreateRunspace()
        $newRunspace.Open()
        $newRunspace.SessionStateProxy.setVariable("client", $client)
        $newPowerShell = [PowerShell]::Create()
        $newPowerShell.Runspace = $newRunspace
        $process = {
            
            

            function Invoke-CreateCertificate([string] $certSubject)
            {
               [console]::WriteLine("Create Dynamic Cert + $certSubJect")
               $selfsignCA =  Get-ChildItem cert:\LocalMachine\My| Where-Object { $_.Subject -match "__Interceptor_Trusted_Root" }
               $cert = New-SelfSignedCertificate -certstorelocation cert:\Localmachine\My -Subject $certSubject -DnsName $certSubject -Signer $selfsignCA[0] -Type Custom 
               [console]::WriteLine($cert.Thumbprint)

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
		
		            foreach($s in $rawHeaders)
		            {
			            #We'll handle setting cookies later
			            if($s -eq "Set-Cookie") { Continue }
			            if($s -eq "Transfer-Encoding") 
			            {
				            $transferEncoding = $true
				            continue
			            }
			            [void]$rawHeadersString.AppendLine($s + ": " + $rawHeaderCollection.Get($s) ) #Use [void] or you will get extra string stuff.
		            }	
		            $setCookieString = $rawHeaderCollection.Get("Set-Cookie") -Split '($|,(?! ))' #Split on "," but not ", "
		            if($setCookieString)
		            {
			            foreach ($respCookie in $setCookieString)
			            {
				            if($respCookie -eq "," -Or $respCookie -eq "") {continue}
				            [void]$rawHeadersString.AppendLine("Set-Cookie: " + $respCookie) 
			            }
		            }
		
		            $responseStream = $response.GetResponseStream()
		
		            $rstring = $rawProtocolVersion + " " + $rawStatusCode + " " + $rawStatusDescription + "`r`n" + $rawHeadersString.ToString() + "`r`n"
		
		            [byte[]] $rawHeaderBytes = [System.Text.Encoding]::Ascii.GetBytes($rstring)
		
		            Write-Host $rstring 
		
		            [void][byte[]] $outdata 
		            $tempMemStream = New-Object System.IO.MemoryStream
		            [byte[]] $respbuffer = New-Object Byte[] 32768 # 32768
		
		            if($transferEncoding)
		            {
			            $reader = New-Object System.IO.StreamReader($responseStream)
			            [string] $responseFromServer = $reader.ReadToEnd()
			
			            if ($Tamper)
			            {
				            if($responseFromServer -match 'Cyber')
				            {
					            $responseFromServer = $responseFromServer -replace 'Cyber', 'Kitten'
				            }
			            }
			
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
		
			            if ($Tamper -And $response.ContentType -match "text/html")
			            {
				
				            $outdataReplace = [System.Text.Encoding]::UTF8.GetString($outdata)
				            if($outdataReplace -match 'Cyber')
				            {
					            $outdataReplace = $outdataReplace -Replace 'Cyber', 'Kitten' 
					            $outdata = [System.Text.Encoding]::UTF8.GetBytes($outdataReplace)
				            }
				
				
			            }
		            }
		            [byte[]] $rv = New-Object Byte[] ($rawHeaderBytes.Length + $outdata.Length)
		            #Combine Header Bytes and Entity Bytes 
		
		            [System.Buffer]::BlockCopy( $rawHeaderBytes, 0, $rv, 0, $rawHeaderBytes.Length)
		            [System.Buffer]::BlockCopy( $outdata, 0, $rv, $rawHeaderBytes.Length, $outdata.Length ) 
	
		
		            $tempMemStream.Close()
		            $response.Close()
		
		            return $rv
	            }
	            Catch [System.Exception]
	            {
		            [Console]::WriteLine("Get Response Error")
		            [Console]::WriteLine($_.Exception.Message)
                }#End Catch
	
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
		            $request.AllowAutoRedirect = $false 
		            $request.AutomaticDecompression = [System.Net.DecompressionMethods]::None
	
		            For ($i = 1; $i -le $requestString.Length; $i++)
		            {
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
					            "User-Agent" { $request.UserAgent = $line[1]  + " Intercepted Traffic"} 
					            # Added Tampering Here...User-Agent Example
					            "Transfer-Encoding"  { $request.TransferEncoding = $line[1] } 
					            default {
								            if($line[0] -eq "Accept-Encoding")
								            {	
									            $request.Headers.Add( $line[0], " ") #Take that Gzip...
									            #Otherwise have to decompress response to tamper with content...
								            }
								            else
								            {
									            $request.Headers.Add( $line[0], $line[1])
								            }	
	
							            }
				            }
				
			            }
			            Catch
			            {
				
			            }
		            }
			
		            if (($httpMethod -eq "POST") -And ($request.ContentLength -gt 0)) 
		            {
			            [System.IO.Stream] $outputStream = [System.IO.Stream]$request.GetRequestStream()
			            $outputStream.Write($requestBytes, $requestBytes.Length - $request.ContentLength, $request.ContentLength)
			            $outputStream.Close()
		            }
		
		
		            return Receive-ServerHttpResponse $request.GetResponse()
		
	            }
	            Catch [System.Net.WebException]
	            {
		            #HTTPWebRequest  Throws exceptions based on Server Response.  So catch and return server response
		            if ($_.Exception.Response) 
		            {
			            return Receive-ServerHttpResponse $_.Exception.Response
                    }
			
                }#End Catch Web Exception
	            Catch [System.Exception]
	            {	
		            Write-Verbose $_.Exception.Message
	            }#End General Exception Occured...
	
            }#Proxied Get

            function Receive-ClientHttpRequest([System.Net.Sockets.TcpClient] $client, [System.Net.WebProxy] $proxy)
            {
	
	            Try
	            {	
		            $clientStream = $client.GetStream()
		            $byteArray = new-object System.Byte[] 32768 
		            [void][byte[]] $byteClientRequest

		            do 
		             {
			            [int] $NumBytesRead = $clientStream.Read($byteArray, 0, $byteArray.Length) 
			            $byteClientRequest += $byteArray[0..($NumBytesRead - 1)]  
		 
		             } While ($clientStream.DataAvailable -And $NumBytesRead -gt 0) 
			

		            #Now you have a byte[] Get a string...  Caution, not all that is sent is "string" Headers will be.
		            $requestString = [System.Text.Encoding]::UTF8.GetString($byteClientRequest)
                    [console]::WriteLine($requestString)
		
		            [string[]] $requestArray = ($requestString -split '[\r\n]') |? {$_} 
		            [string[]] $methodParse = $requestArray[0] -split " "
		            #Begin SSL MITM IF Request Contains CONNECT METHOD

		            

		            if($methodParse[0] -ceq "CONNECT")
		            {
			            [string[]] $domainParse = $methodParse[1].Split(":")
			            
                        [console]::WriteLine("Inside CONNECT")
                        [console]::WriteLine($domainParse[0])
			            $connectSpoof = [System.Text.Encoding]::Ascii.GetBytes("HTTP/1.1 200 Connection Established`r`nTimeStamp: " + [System.DateTime]::Now.ToString() + "`r`n`r`n")
			            $clientStream.Write($connectSpoof, 0, $connectSpoof.Length)	
			            $clientStream.Flush()
			            $sslStream = New-Object System.Net.Security.SslStream($clientStream , $false)
			            $sslStream.ReadTimeout = 500
			            $sslStream.WriteTimeout = 500
			            $sslcertfake = (Get-ChildItem Cert:\LocalMAchine\My | Where-Object {$_.Subject -eq "CN=" + $domainParse[0] })
			            
                        
			            if ($sslcertfake -eq $null)
			            {
				            $sslcertfake =  Invoke-CreateCertificate $domainParse[0]
			            }
			            
			            $sslStream.AuthenticateAsServer($sslcertfake, $false, [System.Security.Authentication.SslProtocols]::Tls12, $false)
		
			            $sslbyteArray = new-object System.Byte[] 32768
			            [void][byte[]] $sslbyteClientRequest
			
			            do 
			                {
				            [int] $NumBytesRead = $sslStream.Read($sslbyteArray, 0, $sslbyteArray.Length) 
				            $sslbyteClientRequest += $sslbyteArray[0..($NumBytesRead - 1)]  
			                } while ( $clientStream.DataAvailable  )
			
			            $SSLRequest = [System.Text.Encoding]::UTF8.GetString($sslbyteClientRequest)
			            
                        
			
			            [string[]] $SSLrequestArray = ($SSLRequest -split '[\r\n]') |? {$_} 
			            [string[]] $SSLmethodParse = $SSLrequestArray[0] -split " "
			
			            $secureURI = "https://" + $domainParse[0] + $SSLmethodParse[1]
			            

			            [byte[]] $byteResponse =  Send-ServerHttpRequest $secureURI $SSLmethodParse[0] $sslbyteClientRequest $proxy
                        
			
			            if($byteResponse[0] -eq '0x00')
			            {
				            $sslStream.Write($byteResponse, 1, $byteResponse.Length - 1)
			            }
			            else
			            {
				            $sslStream.Write($byteResponse, 0, $byteResponse.Length )
			            }
			            
                       
			            
			
		            }#End CONNECT/SSL Processing
		            Else
		            {
                        [console]::WriteLine($requestString)

			            [byte[]] $proxiedResponse = Send-ServerHttpRequest $methodParse[1] $methodParse[0] $byteClientRequest $proxy
			            if($proxiedResponse[0] -eq '0x00')
			            {
				            $clientStream.Write($proxiedResponse, 1, $proxiedResponse.Length - 1 )	
			            }
			            else
			            {
				            $clientStream.Write($proxiedResponse, 0, $proxiedResponse.Length )	
			            }
			
		            }#End Http Proxy
		            
		
	            }# End HTTPProcessing Block
	            Catch
	            {
		            Write-Verbose $_.Exception.Message
		            
	            }
	            
               $client.Close()
            }





            #[console]::WriteLine("Inside Processing")

            
            Receive-ClientHttpRequest $client 
            


        }
        $jobHandle = $newPowerShell.AddScript($process).BeginInvoke()
        #jobHandle you need to save for future to cleanup
    }
}

$listener = {
    $Listener['listener'] = New-Object System.Net.Sockets.TcpListener("127.0.0.1", "8888")
    $Listener['listener'].Start()
    [console]::WriteLine("Listening on :8888")



    while ($true) {
        $c = $Listener['listener'].AcceptTcpClient()
        If($c -ne $Null) {
            [console]::WriteLine("{0} >> Accepted Client " -f (Get - Date).ToString())
            $CnQueue.Enqueue($c)
        }
        Else {
            [console]::WriteLine("Shutting down")
            Break
        }
    }
}


# Create And Install Trusted Root CA.
Invoke-RemoveCertificates "__Interceptor_Trusted_Root"
Invoke-CreateCACertificate "__Interceptor_Trusted_Root"

$Timer.Start()
$Global:handle = $newPowerShell.AddScript($listener).BeginInvoke()
