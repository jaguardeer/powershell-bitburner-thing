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
    $sock.Listen()
    $sock
}

function Poll-Socket
{
    Param(
        [Parameter(Mandatory)]
        [Socket] $Socket
    )
    while ( -not $Socket.Poll(1e4, [SelectMode]::SelectRead) )
    {
        Start-Sleep -Milliseconds 1
    }
}

function Read-Socket
{
    Param(
        [Parameter(Mandatory)]
        [Socket] $Socket
    )
    Poll-Socket -Socket $Socket
    $ReceiveBuffer = [byte[]]::new($clientSocket.Available)
    $BytesReceived = $clientSocket.Receive($ReceiveBuffer)
    $ReceiveBuffer
}

function Upgrade-WebSocket
{
    Param(
        [Parameter(Mandatory)]
        [Socket] $Socket
    )
    $headers = Parse-Headers (Read-Socket -Socket $Socket)
    # Accept WebSockets Connection
    $SecWebSocketAccept = Generate-SecWebSocketAccept $headers."Sec-WebSocket-Key"
    $responseLines = "HTTP/1.1 101 Switching Protocols", "Upgrade: websocket",
        "Connection: Upgrade", "Sec-WebSocket-Accept: $SecWebSocketAccept", "", ""
    $responseBytes = [Encoding]::UTF8.GetBytes($responseLines -join "`r`n")
    $bytesSent = $clientSocket.Send($responseBytes)
    Write-Host "Sent $bytesSent bytes for WebSocket upgrade"
}

function Get-ClientSocket
{
    Param(
        [Parameter(Mandatory)]
        [Socket] $Socket
    )
    $Task = $Socket.AcceptAsync()
    while ( $Task.Status -eq [System.Threading.Tasks.TaskStatus]::WaitingForActivation )
    {
        Start-Sleep -Milliseconds 1
    }
    $Task.GetAwaiter().GetResult()
}

function Send-WebSocketMessage
{
    Param(
        [Parameter(Mandatory)]
        [Socket] $Socket,
        [Parameter(Mandatory)]
        [string] $Message
    )
    $msg = [System.Text.Encoding]::UTF8.GetBytes($Message)

    $headerFlags = [byte[]] 0x81
    $headerPayloadLength = switch($msg.Length)
    {
        {$_ -lt 126}  { [byte[]] $msg.Length; break } # 0–125 = This is the payload length.
        {$_ -lt (1 -shl 16)} { 126; Write-Host "TODO!!!"; exit; break } # 126 = The following 16 bits are the payload length.
        {$_ -lt (1 -shl 64)} { 127; Write-Host "TODO!!!"; exit; break } # 127 = The following 64 bits (MSB must be 0) are the payload length.
        default { Write-Host "TODO!! Message needs fragmentation"; exit }
    }
    $buffer = $headerFlags + $headerPayloadLength + $msg
    $sentBytes = $Socket.Send($buffer)

    Write-Host "Sent $sentBytes bytes"
}

function TestFunc
{
    Param(
        [Parameter(Mandatory)] $ListenSocket
    )
    Poll-Socket -Socket $ListenSocket
    $ClientSocket = $ListenSocket.Accept()
    $buffer = Read-Socket -Socket $ClientSocket
    #$bytesReceived = $clientSocket.Receive($buffer)
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
        $ReceiveBuffer = Read-Socket -Socket $ClientSocket
        Write-Host "Received $bytesReceived bytes"

        # parse received websocket msg
        $flags, $maskedLength = $ReceiveBuffer[0..1]
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
        $maskedKey = $ReceiveBuffer[$maskOffset..($maskOffset + 3)]
        Write-Host "maskOffset is $maskOffset"
        Write-Host "maskedKey is 0x$(($maskedKey | % { "{0:x2}" -f $_ }) -join '')"
        $unmaskedBuffer = for ( $i = $maskOffset + 4 ; $i -lt $ReceiveBuffer.Count ; $i++ )
        {
            # todo 4 at a time?
            $ReceiveBuffer[$i] -bxor $maskedKey[$i % 4]
        }
        $msg += [Encoding]::UTF8.GetString($unmaskedBuffer)
        $msg
    }
}
