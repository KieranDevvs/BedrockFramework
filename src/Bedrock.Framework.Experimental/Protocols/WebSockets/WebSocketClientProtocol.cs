using System;
using System.Buffers;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Connections;

namespace Bedrock.Framework.Experimental.Protocols.WebSockets;

/// <summary>
/// The client side of the RFC 6455 opening handshake over an HTTP/1.1 connection.
/// </summary>
public static class WebSocketClientProtocol
{
    /// <summary>
    /// Sends the upgrade request over an already established connection (plain or TLS), validates the server's
    /// response and returns the open session.
    /// </summary>
    /// <param name="connection">The connection to the server. Use TLS middleware on the client for wss:// URIs.</param>
    /// <param name="uri">The ws:// or wss:// URI. Its host, port, path and query form the request.</param>
    /// <param name="options">Client options.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <exception cref="WebSocketHandshakeException">The server rejected or improperly answered the upgrade request.</exception>
    public static async ValueTask<WebSocketSession> ConnectAsync(ConnectionContext connection, Uri uri, WebSocketClientOptions options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(uri);
        options ??= new WebSocketClientOptions();
        options.Validate();

        if (!uri.IsAbsoluteUri || uri.Scheme is not ("ws" or "wss" or "http" or "https"))
        {
            throw new ArgumentException("The URI must be an absolute ws://, wss://, http:// or https:// URI.", nameof(uri));
        }

        foreach (var protocol in options.SubProtocols)
        {
            if (!WebSocketHandshake.IsToken(protocol))
            {
                throw new ArgumentException($"'{protocol}' is not a valid subprotocol token.", nameof(options));
            }
        }

        var key = WebSocketHandshake.GenerateKey();
        var target = string.IsNullOrEmpty(uri.PathAndQuery) ? "/" : uri.PathAndQuery;

        var request = new StringBuilder();
        request.Append("GET ").Append(target).Append(" HTTP/1.1\r\n");
        request.Append("Host: ").Append(WebSocketHandshake.GetHostHeader(uri)).Append("\r\n");
        request.Append("Upgrade: websocket\r\n");
        request.Append("Connection: Upgrade\r\n");
        request.Append(WebSocketHandshake.HeaderKey).Append(": ").Append(key).Append("\r\n");
        request.Append(WebSocketHandshake.HeaderVersion).Append(": ").Append(WebSocketHandshake.SupportedVersion).Append("\r\n");
        if (options.Origin != null)
        {
            request.Append(WebSocketHandshake.HeaderOrigin).Append(": ").Append(options.Origin).Append("\r\n");
        }
        if (options.SubProtocols.Count > 0)
        {
            request.Append(WebSocketHandshake.HeaderProtocol).Append(": ").Append(string.Join(", ", options.SubProtocols)).Append("\r\n");
        }
        if (options.Compression != null)
        {
            request.Append(WebSocketHandshake.HeaderExtensions).Append(": ").Append(PerMessageDeflateParameters.CreateClientOffer(options.Compression)).Append("\r\n");
        }
        foreach (var (name, value) in options.Headers)
        {
            if (!WebSocketHandshake.IsToken(name) || value.AsSpan().IndexOfAny('\r', '\n') >= 0)
            {
                throw new ArgumentException($"The header '{name}' is not valid.", nameof(options));
            }
            request.Append(name).Append(": ").Append(value).Append("\r\n");
        }
        request.Append("\r\n");

        var output = connection.Transport.Output;
        output.Write(Encoding.Latin1.GetBytes(request.ToString()));
        await output.FlushAsync(cancellationToken).ConfigureAwait(false);

        var head = await HttpHead.ReadAsync(connection.Transport.Input, isRequest: false, options.MaxHandshakeSize, cancellationToken).ConfigureAwait(false)
            ?? throw new WebSocketHandshakeException(null, "The server closed the connection without responding to the upgrade request.");

        if (!head.First.StartsWith("HTTP/1.", StringComparison.Ordinal) || !int.TryParse(head.Second, out var status))
        {
            throw new WebSocketHandshakeException(null, "The server sent a malformed HTTP response.");
        }

        if (status != 101)
        {
            throw new WebSocketHandshakeException(status, $"The server rejected the WebSocket upgrade with status {status} {head.Third}.", head.Headers);
        }

        WebSocketHandshakeException Invalid(string message) => new(status, message, head.Headers);

        if (!WebSocketHandshake.ContainsToken(head[WebSocketHandshake.HeaderUpgrade], "websocket"))
        {
            throw Invalid("The server response is missing 'Upgrade: websocket'.");
        }

        if (!WebSocketHandshake.ContainsToken(head[WebSocketHandshake.HeaderConnection], "Upgrade"))
        {
            throw Invalid("The server response is missing 'Connection: Upgrade'.");
        }

        var accept = head[WebSocketHandshake.HeaderAccept];
        if (accept.Count != 1 || !string.Equals(accept.ToString().Trim(), WebSocketHandshake.ComputeAcceptKey(key), StringComparison.Ordinal))
        {
            throw Invalid("The server response has a missing or incorrect Sec-WebSocket-Accept.");
        }

        string subProtocol = null;
        var protocols = WebSocketHandshake.ParseTokenList(head[WebSocketHandshake.HeaderProtocol]);
        if (protocols.Count > 1)
        {
            throw Invalid("The server selected more than one subprotocol.");
        }
        if (protocols.Count == 1)
        {
            subProtocol = protocols[0];
            if (!options.SubProtocols.Contains(subProtocol, StringComparer.Ordinal))
            {
                throw Invalid($"The server selected the subprotocol '{subProtocol}', which was not offered.");
            }
        }

        PerMessageDeflateParameters compression = null;
        try
        {
            foreach (var extension in WebSocketExtension.Parse(head[WebSocketHandshake.HeaderExtensions]))
            {
                if (options.Compression == null || compression != null
                    || !string.Equals(extension.Name, PerMessageDeflateParameters.ExtensionName, StringComparison.OrdinalIgnoreCase))
                {
                    throw Invalid($"The server accepted the extension '{extension.Name}', which was not offered.");
                }

                compression = PerMessageDeflateParameters.ValidateServerResponse(extension, options.Compression);
            }
        }
        catch (FormatException ex)
        {
            throw Invalid(ex.Message);
        }

        return WebSocketSession.Create(connection, isServer: false, options, subProtocol, compression);
    }
}
