using System;
using System.IO;
using System.IO.Pipelines;
using System.Linq;
using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Bedrock.Framework.Experimental.Protocols.WebSockets;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Bedrock.Framework.Protocols.WebSockets.Tests;

/// <summary>
/// End-to-end tests over real loopback sockets against the .NET WebSocket client and the Kestrel WebSocket server.
/// </summary>
public class WebSocketEndToEndTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task BedrockServerInteropsWithClientWebSocket(bool compress, bool tls)
    {
        using var certificate = tls ? CreateCertificate() : null;
        var serviceProvider = new ServiceCollection().AddLogging().BuildServiceProvider();

        var server = new ServerBuilder(serviceProvider)
            .UseSockets(sockets => sockets.Listen(IPAddress.Loopback, 0, builder =>
            {
                if (tls)
                {
                    builder.UseServerTls(options =>
                    {
                        options.LocalCertificate = certificate;
                        options.RemoteCertificateMode = Bedrock.Framework.Middleware.Tls.RemoteCertificateMode.NoCertificate;
                    });
                }

                builder.RunWebSocket(async (session, request) =>
                {
                    Assert.Equal("/echo", request.Path);
                    while (true)
                    {
                        var message = await session.ReadMessageAsync();
                        if (message.MessageType == WebSocketMessageType.Close)
                        {
                            return;
                        }
                        await session.SendAsync(message.Data, message.MessageType);
                    }
                }, options =>
                {
                    options.KeepAliveInterval = TimeSpan.Zero;
                    options.SubProtocols.Add("echo.v1");
                    if (compress)
                    {
                        options.Compression = new WebSocketCompressionOptions();
                    }
                });
            }))
            .Build();

        await server.StartAsync();
        try
        {
            var port = ((IPEndPoint)server.EndPoints.Single()).Port;

            using var client = new ClientWebSocket();
            client.Options.CollectHttpResponseDetails = true;
            client.Options.AddSubProtocol("echo.v1");
            if (compress)
            {
                client.Options.DangerousDeflateOptions = new WebSocketDeflateOptions();
            }
            if (tls)
            {
                client.Options.RemoteCertificateValidationCallback = (_, _, _, _) => true;
            }

            await client.ConnectAsync(new Uri($"{(tls ? "wss" : "ws")}://127.0.0.1:{port}/echo"), default).WaitAsync(Timeout);
            Assert.Equal("echo.v1", client.SubProtocol);
            Assert.Equal(compress, client.HttpResponseHeaders?.ContainsKey("Sec-WebSocket-Extensions") ?? false);

            foreach (var size in new[] { 0, 10, 1000, 200_000 })
            {
                var payload = Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("bedrock ", size / 8 + 1)))[..size];
                await client.SendAsync(payload, WebSocketMessageType.Text, true, default).WaitAsync(Timeout);
                var (type, echoed) = await ReceiveAsync(client);
                Assert.Equal(WebSocketMessageType.Text, type);
                Assert.Equal(payload, echoed);
            }

            await client.CloseAsync(WebSocketCloseStatus.NormalClosure, "done", default).WaitAsync(Timeout);
            Assert.Equal(WebSocketState.Closed, client.State);
            Assert.Equal(WebSocketCloseStatus.NormalClosure, client.CloseStatus);
        }
        finally
        {
            await server.StopAsync();
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BedrockClientInteropsWithKestrel(bool compress)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        await using var app = builder.Build();

        string negotiatedExtensions = null;
        app.UseWebSockets();
        app.Map("/echo", async context =>
        {
            negotiatedExtensions = context.Request.Headers["Sec-WebSocket-Extensions"];
            using var socket = await context.WebSockets.AcceptWebSocketAsync(new WebSocketAcceptContext
            {
                SubProtocol = context.WebSockets.WebSocketRequestedProtocols.FirstOrDefault(),
                DangerousEnableCompression = compress,
            });

            var buffer = new byte[1024 * 1024];
            while (true)
            {
                var stream = new MemoryStream();
                ValueWebSocketReceiveResult result;
                do
                {
                    result = await socket.ReceiveAsync(buffer.AsMemory(), default);
                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        await socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "server bye", default);
                        return;
                    }
                    stream.Write(buffer, 0, result.Count);
                }
                while (!result.EndOfMessage);

                await socket.SendAsync(stream.ToArray(), result.MessageType, true, default);
            }
        });

        await app.StartAsync();
        var address = new Uri(app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>().Addresses.First());

        var client = new ClientBuilder().UseSockets().Build();
        await using var connection = await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, address.Port)).AsTask().WaitAsync(Timeout);

        var options = new WebSocketClientOptions { KeepAliveInterval = TimeSpan.Zero, Compression = compress ? new WebSocketCompressionOptions() : null };
        options.SubProtocols.Add("echo.v1");
        await using var session = await connection.ConnectWebSocketAsync(new Uri($"ws://127.0.0.1:{address.Port}/echo"), options).AsTask().WaitAsync(Timeout);

        Assert.Equal("echo.v1", session.SubProtocol);
        Assert.Equal(compress, session.Compression != null);
        Assert.Equal(compress, negotiatedExtensions?.Contains("permessage-deflate") ?? false);

        foreach (var size in new[] { 0, 10, 1000, 300_000 })
        {
            var payload = new byte[size];
            new Random(size).NextBytes(payload.AsSpan(0, size / 3));

            // Send the larger messages in fragments
            if (size > 1000)
            {
                await session.SendAsync(payload.AsMemory(0, 1000), WebSocketMessageType.Binary, endOfMessage: false).AsTask().WaitAsync(Timeout);
                await session.SendAsync(payload.AsMemory(1000), WebSocketMessageType.Binary, endOfMessage: true).AsTask().WaitAsync(Timeout);
            }
            else
            {
                await session.SendAsync(payload, WebSocketMessageType.Binary).AsTask().WaitAsync(Timeout);
            }

            var message = await session.ReadMessageAsync().AsTask().WaitAsync(Timeout);
            Assert.Equal(WebSocketMessageType.Binary, message.MessageType);
            Assert.Equal(payload, message.Data.ToArray());
        }

        await session.CloseAsync(WebSocketCloseStatus.NormalClosure, "client bye").AsTask().WaitAsync(Timeout);
        Assert.Equal(WebSocketState.Closed, session.State);
        Assert.Equal(WebSocketCloseStatus.NormalClosure, session.CloseStatus);
        Assert.Equal("server bye", session.CloseStatusDescription);

        await app.StopAsync();
    }

    [Fact]
    public async Task BedrockPipelinesRunOverWebSocketMiddleware()
    {
        var serviceProvider = new ServiceCollection().AddLogging().BuildServiceProvider();
        var serverSawFeature = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

        // An ordinary byte-stream echo application, running over WebSockets on both ends
        var server = new ServerBuilder(serviceProvider)
            .UseSockets(sockets => sockets.Listen(IPAddress.Loopback, 0, builder => builder
                .UseWebSocketServer(options =>
                {
                    options.KeepAliveInterval = TimeSpan.Zero;
                    options.Compression = new WebSocketCompressionOptions();
                }, path: "/pipe")
                .Run(async connection =>
                {
                    serverSawFeature.TrySetResult(connection.Features.Get<IWebSocketSessionFeature>()?.Request?.Path);
                    await connection.Transport.Input.CopyToAsync(connection.Transport.Output);
                })))
            .Build();

        await server.StartAsync();
        try
        {
            var port = ((IPEndPoint)server.EndPoints.Single()).Port;

            var client = new ClientBuilder(serviceProvider)
                .UseSockets()
                .UseWebSocketClient(new Uri($"ws://127.0.0.1:{port}/pipe"), options =>
                {
                    options.KeepAliveInterval = TimeSpan.Zero;
                    options.Compression = new WebSocketCompressionOptions();
                })
                .Build();

            await using var connection = await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port)).AsTask().WaitAsync(Timeout);
            Assert.NotNull(connection.Features.Get<IWebSocketSessionFeature>().Session.Compression);

            var payload = Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("over the wire ", 5000)));
            await connection.Transport.Output.WriteAsync(payload).AsTask().WaitAsync(Timeout);

            var received = new MemoryStream();
            while (received.Length < payload.Length)
            {
                var result = await connection.Transport.Input.ReadAsync().AsTask().WaitAsync(Timeout);
                foreach (var segment in result.Buffer)
                {
                    received.Write(segment.Span);
                }
                connection.Transport.Input.AdvanceTo(result.Buffer.End);
            }

            Assert.Equal(payload, received.ToArray());
            Assert.Equal("/pipe", await serverSawFeature.Task.WaitAsync(Timeout));
        }
        finally
        {
            await server.StopAsync();
        }
    }

    [Fact]
    public async Task WebSocketServerMiddlewareRejectsOtherPaths()
    {
        var serviceProvider = new ServiceCollection().AddLogging().BuildServiceProvider();
        var server = new ServerBuilder(serviceProvider)
            .UseSockets(sockets => sockets.Listen(IPAddress.Loopback, 0, builder => builder
                .UseWebSocketServer(path: "/only-here")
                .Run(connection => connection.Transport.Input.CopyToAsync(connection.Transport.Output))))
            .Build();

        await server.StartAsync();
        try
        {
            var port = ((IPEndPoint)server.EndPoints.Single()).Port;
            using var client = new ClientWebSocket();
            client.Options.CollectHttpResponseDetails = true;

            var ex = await Assert.ThrowsAsync<WebSocketException>(() => client.ConnectAsync(new Uri($"ws://127.0.0.1:{port}/elsewhere"), default).WaitAsync(Timeout));
            Assert.Equal(HttpStatusCode.NotFound, client.HttpStatusCode);
        }
        finally
        {
            await server.StopAsync();
        }
    }

    [Fact]
    public async Task ProtocolViolationsOverRealSocketsDeliverTheCloseFrameRatherThanAReset()
    {
        var serviceProvider = new ServiceCollection().AddLogging().BuildServiceProvider();
        var server = new ServerBuilder(serviceProvider)
            .UseSockets(sockets => sockets.Listen(IPAddress.Loopback, 0, builder => builder.RunWebSocket(async (session, _) =>
            {
                try
                {
                    while ((await session.ReadMessageAsync()).MessageType != WebSocketMessageType.Close)
                    {
                    }
                }
                catch (WebSocketException)
                {
                    // Expected: the client violates the protocol
                }
            }, options => options.KeepAliveInterval = TimeSpan.Zero)))
            .Build();

        await server.StartAsync();
        try
        {
            var port = ((IPEndPoint)server.EndPoints.Single()).Port;

            // Repeat: aborting too early is a race, so a single attempt can pass by luck
            for (var attempt = 0; attempt < 25; attempt++)
            {
                using var client = new System.Net.Sockets.TcpClient { NoDelay = true };
                await client.ConnectAsync(IPAddress.Loopback, port);
                var stream = client.GetStream();

                var key = WebSocketHandshake.GenerateKey();
                await stream.WriteAsync(Encoding.ASCII.GetBytes(
                    $"GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"));

                var head = new StringBuilder();
                var one = new byte[1];
                while (!head.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal))
                {
                    await stream.ReadExactlyAsync(one);
                    head.Append((char)one[0]);
                }
                Assert.StartsWith("HTTP/1.1 101", head.ToString());

                // An unmasked text frame from a client, followed by more data the server will not read
                await stream.WriteAsync(new byte[] { 0x81, 0x02, (byte)'h', (byte)'i', 0x81, 0x01, (byte)'!' });

                var header = new byte[2];
                await stream.ReadExactlyAsync(header).AsTask().WaitAsync(Timeout);
                Assert.Equal(0x88, header[0]);
                var body = new byte[header[1] & 0x7F];
                await stream.ReadExactlyAsync(body).AsTask().WaitAsync(Timeout);
                Assert.Equal(1002, System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(body));
            }
        }
        finally
        {
            await server.StopAsync();
        }
    }

    [Fact]
    public async Task FailingAfterTheApplicationSentCloseStillDeliversTheCloseFrame()
    {
        var serviceProvider = new ServiceCollection().AddLogging().BuildServiceProvider();
        var server = new ServerBuilder(serviceProvider)
            .UseSockets(sockets => sockets.Listen(IPAddress.Loopback, 0, builder => builder.RunWebSocket(async (session, _) =>
            {
                try
                {
                    await session.ReadMessageAsync();
                    await session.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "app done");

                    // Keep reading for the peer's Close; the peer misbehaves instead
                    while ((await session.ReadMessageAsync()).MessageType != WebSocketMessageType.Close)
                    {
                    }
                }
                catch (WebSocketException)
                {
                }
            }, options => options.KeepAliveInterval = TimeSpan.Zero)))
            .Build();

        await server.StartAsync();
        try
        {
            var port = ((IPEndPoint)server.EndPoints.Single()).Port;
            for (var attempt = 0; attempt < 15; attempt++)
            {
                using var client = new System.Net.Sockets.TcpClient { NoDelay = true };
                await client.ConnectAsync(IPAddress.Loopback, port);
                var stream = client.GetStream();

                await stream.WriteAsync(Encoding.ASCII.GetBytes(
                    $"GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {WebSocketHandshake.GenerateKey()}\r\nSec-WebSocket-Version: 13\r\n\r\n"));
                var head = new StringBuilder();
                var one = new byte[1];
                while (!head.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal))
                {
                    await stream.ReadExactlyAsync(one);
                    head.Append((char)one[0]);
                }

                // A valid masked text frame "a", then (without reading the server's Close) an unmasked frame and more data
                await stream.WriteAsync(new byte[] { 0x81, 0x81, 1, 2, 3, 4, (byte)('a' ^ 1) });
                await Task.Delay(50);
                var violation = new byte[256 * 1024];
                new byte[] { 0x81, 0x02, (byte)'h', (byte)'i' }.CopyTo(violation, 0);
                try
                {
                    await stream.WriteAsync(violation);
                }
                catch (System.IO.IOException)
                {
                    // The server may stop reading once it has failed the connection
                }

                var header = new byte[2];
                await stream.ReadExactlyAsync(header).AsTask().WaitAsync(Timeout);
                Assert.Equal(0x88, header[0]);
                var body = new byte[header[1] & 0x7F];
                await stream.ReadExactlyAsync(body).AsTask().WaitAsync(Timeout);
                Assert.Equal(1000, System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(body));
            }
        }
        finally
        {
            await server.StopAsync();
        }
    }

    private static async Task<(WebSocketMessageType, byte[])> ReceiveAsync(WebSocket socket)
    {
        var buffer = new byte[64 * 1024];
        var stream = new MemoryStream();
        ValueWebSocketReceiveResult result;
        do
        {
            result = await socket.ReceiveAsync(buffer.AsMemory(), default).AsTask().WaitAsync(Timeout);
            stream.Write(buffer, 0, result.Count);
        }
        while (!result.EndOfMessage);

        return (result.MessageType, stream.ToArray());
    }

    private static X509Certificate2 CreateCertificate()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddIpAddress(IPAddress.Loopback);
        san.AddDnsName("localhost");
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));

        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        // Round-trip through PFX so the private key is usable by SslStream on every platform
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), null);
#else
        return new X509Certificate2(certificate.Export(X509ContentType.Pfx));
#endif
    }
}
