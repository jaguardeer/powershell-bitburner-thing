using namespace System.Net.Sockets
using namespace System.Text

function Parse-Headers
{
	Param(
        $msgBytes
	)

	$msgString = [Encoding]::UTF8.GetString($msgBytes);

	$headerLines = $msgString -split "`r`n";

    $headerDict = @{}
    foreach ( $line in $headerLines ) {
        $splitPos = $line.IndexOf(":");
        if ( $splitPos -lt 0 )
        {
            Write-Information "Couldn't parse header line: $line";
            continue;
        }
        $headerName = $line.Substring(0, $splitPos).Trim();
        $headerValue = $line.Substring($splitPos + 1, $line.Length - $splitPos - 1).Trim();
        Write-Information "$headerName = $headerValue";
        $headerDict[$headerName] = $headerValue
    }
    $headerDict
}

function Generate-SecWebSocketAccept
{
    Param(
        $SecWebSocketKey
    )
    $SecWebSocketSuffix = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    $Bytes = [Encoding]::UTF8.GetBytes($SecWebSocketKey + $SecWebSocketSuffix)
    $Sha1 = [System.Security.Cryptography.SHA1CryptoServiceProvider]::new()
    $SecWebSocketAccept = [System.Convert]::ToBase64String($Sha1.ComputeHash($Bytes))
    $SecWebSocketAccept
}

function Generate-JsonRpcMessage
{
    # https://github.com/bitburner-official/bitburner-src/blob/dev/src/Documentation/doc/programming/remote_api.md
    $msgString = "{`"jsonrpc`":`"2.0`",`"id`":0,`"method`":`"getFileNames`",`"params`":{`"server`":`"home`"}}"
    $msgBytes = [Encoding]::UTF8.GetBytes($msgString)

    $header = [byte[]]::new(2)
    $header[0] = 0x81
    $header[1] = $msgBytes.Count

    $header + $msgBytes
}

function Send-JsonRpcMessage
{
    Param(
        [Parameter(Mandatory)] $clientSocket
    )
    $msg = Generate-JsonRpcMessage
    $bytesSent = $clientSocket.Send($msg)
    Write-Host "Sent $bytesSent bytes for JSON-RPC"
}

function Create-ListenerSocket
{
	Param(
        [IPEndPoint] $LocalEp = [IPEndPoint]::new([IPAddress] "127.0.0.1", 80)
    )
    $sock = [Socket]::new([SocketType]::Stream, [ProtocolType]::Tcp)
    $sock.Bind($LocalEp)
    $sock
}

function TestFunc
{
    Param(
        [Parameter(Mandatory)] $listenSocket
    )
    $clientSocket = $listenSocket.Accept()
    $buffer = [byte[]]::new(1024)
    $bytesReceived = $clientSocket.Receive($buffer)
    $headers = Parse-Headers $buffer

    # Accept WebSockets Connection
    $SecWebSocketAccept = Generate-SecWebSocketAccept $headers."Sec-WebSocket-Key"
    $responseLines = "HTTP/1.1 101 Switching Protocols", "Upgrade: websocket",
        "Connection: Upgrade", "Sec-WebSocket-Accept: $SecWebSocketAccept", "", ""
    $responseBytes = [Encoding]::UTF8.GetBytes($responseLines -join "`r`n")
    $bytesSent = $clientSocket.Send($responseBytes)
    Write-Host "Sent $bytesSent bytes for WebSocket upgrade"

    # JSON-RPC stuff
    Send-JsonRpcMessage $clientSocket

    # Try to receive response
    $msg = [String]::Empty
    while ( $true )
    {
        # Get data
        while ( -not $clientSocket.Poll(1e6, [SelectMode]::SelectRead) )
        { <# waiting for data #> }
        $receiveBuffer = [byte[]]::new($clientSocket.Available)
        # Write-Host "There are $bytesAvailable bytes available."
        $bytesReceived = $clientSocket.Receive($receiveBuffer)
        Write-Host "Received $bytesReceived bytes"

        # parse received websocket msg
        $flags, $maskedLength = $receiveBuffer[0..1]
        if ( $flags -ne 0x81 )
        {
            Write-Host "Unknown flags: $("0x{0:X}" -f $flags)"
        }
        if ( ($maskedLength -band 0x80) -ne 0x80 )
        {
            Write-Host "Expected masked but it wasn't"
        }
        $maskOffset = switch($maskedLength -band 0x7F)
        {
            126 { 4; break }
            127 { 10; break }
            default { 2; break }
        }
        $maskedKey = $receiveBuffer[$maskOffset..($maskOffset + 3)]
        Write-Host "maskOffset is $maskOffset"
        Write-Host "maskedKey is 0x$(($maskedKey | % { "{0:x2}" -f $_ }) -join '')"
        $unmaskedBuffer = for ( $i = $maskOffset + 4 ; $i -lt $receiveBuffer.Count ; $i++ )
        {
            # todo 4 at a time?
            $receiveBuffer[$i] -bxor $maskedKey[$i % 4]
        }
        $msg += [Encoding]::UTF8.GetString($unmaskedBuffer)
        $msg
    }
}
