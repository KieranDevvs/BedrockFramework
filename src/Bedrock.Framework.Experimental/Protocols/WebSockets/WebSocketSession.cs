using System;
using System.Buffers;
using System.Buffers.Binary;
using System.IO.Compression;
using System.IO.Pipelines;
using System.Net.WebSockets;
using System.Text;
using System.Text.Unicode;
using System.Threading;
using System.Threading.Tasks;
using Bedrock.Framework.Protocols.WebSockets;
using Microsoft.AspNetCore.Connections;

namespace Bedrock.Framework.Experimental.Protocols.WebSockets;

/// <summary>
/// An open WebSocket session (RFC 6455 sections 5-8) running over a duplex pipe.
/// </summary>
/// <remarks>
/// One read and one send may be in flight at a time, from different threads. Control frames (Ping, Pong, Close)
/// sent by the peer are processed while the session is being read, so keep a read loop running.
/// </remarks>
public sealed class WebSocketSession : IAsyncDisposable
{
    private const int MaxControlPayload = 125;

    private readonly PipeReader _input;
    private readonly PipeWriter _output;
    private readonly bool _isServer;
    private readonly WebSocketSessionOptions _options;
    private readonly long? _maxMessageSize;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly CancellationTokenSource _abortCts = new();
    private readonly TaskCompletionSource _closeReceivedTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly WebSocketFrameWriter _frameWriter = new();

    // permessage-deflate
    private readonly PerMessageDeflater _deflater;
    private readonly PerMessageInflater _inflater;
    private readonly int _minimumCompressedMessageSize;

    // Session state
    private volatile bool _closeSent;
    private volatile bool _closeReceived;
    private volatile bool _aborted;
    private bool _outputCompleted;
    private bool _disposed;
    private WebSocketCloseStatus? _closeStatus;
    private string _closeStatusDescription;

    // Receive state (only touched by the single active reader)
    private int _readInProgress;
    private bool _inFrame;
    private WebSocketHeader _frameHeader;
    private ulong _frameRemaining;
    private WebSocketPayloadEncoder _frameEncoder;
    private bool _inMessage;
    private WebSocketMessageType _messageType;
    private bool _messageCompressed;
    private long _messageLength;
    private Utf8MessageValidator _utf8;
    private byte[] _inflated;
    private int _inflatedOffset;
    private int _inflatedCount;
    private bool _inflatedEndsMessage;

    // Send state (guarded by _writeLock)
    private bool _sendInMessage;
    private bool _sendCompressed;

    // Keep-alive
    private long _lastReceiveTimestamp = Environment.TickCount64;
    private readonly Task _keepAliveTask = Task.CompletedTask;

    private readonly IAsyncDisposable _owner;

    private WebSocketSession(IDuplexPipe transport, bool isServer, WebSocketSessionOptions options, string subProtocol, PerMessageDeflateParameters deflate, ConnectionContext connection, IAsyncDisposable owner)
    {
        _owner = owner;
        ArgumentNullException.ThrowIfNull(transport);
        options ??= new WebSocketSessionOptions();
        options.Validate();

        _input = transport.Input;
        _output = transport.Output;
        _isServer = isServer;
        _options = options;
        _maxMessageSize = options.MaxMessageSize;
        SubProtocol = subProtocol;
        Connection = connection;
        Compression = deflate;

        if (deflate != null)
        {
            var level = options.Compression?.CompressionLevel ?? CompressionLevel.Fastest;
            _minimumCompressedMessageSize = options.Compression?.MinimumMessageSize ?? 0;
            _deflater = new PerMessageDeflater(level, isServer ? deflate.ServerNoContextTakeover : deflate.ClientNoContextTakeover);
            _inflater = new PerMessageInflater(isServer ? deflate.ClientNoContextTakeover : deflate.ServerNoContextTakeover);
        }

        var interval = options.KeepAliveInterval;
        if (interval > TimeSpan.Zero && interval != Timeout.InfiniteTimeSpan)
        {
            _keepAliveTask = KeepAliveLoopAsync(interval, options.KeepAliveTimeout);
        }
    }

    /// <summary>
    /// Creates a session over a transport on which the opening handshake has already completed, for example
    /// a custom upgrade path or an RFC 8441 HTTP/2 stream.
    /// </summary>
    /// <param name="transport">The upgraded transport.</param>
    /// <param name="isServer">Whether this endpoint is the server. Clients mask outgoing frames; servers require masked incoming frames.</param>
    /// <param name="options">Session options.</param>
    /// <param name="subProtocol">The negotiated subprotocol, if any.</param>
    /// <param name="compression">The negotiated permessage-deflate parameters, or null if compression was not negotiated.</param>
    public static WebSocketSession Create(IDuplexPipe transport, bool isServer, WebSocketSessionOptions options = null, string subProtocol = null, PerMessageDeflateParameters compression = null)
        => new(transport, isServer, options, subProtocol, compression, connection: null, owner: null);

    internal static WebSocketSession Create(IDuplexPipe transport, ConnectionContext connection, bool isServer, WebSocketSessionOptions options, string subProtocol, PerMessageDeflateParameters compression, IAsyncDisposable owner = null)
        => new(transport, isServer, options, subProtocol, compression, connection, owner);

    /// <summary>
    /// The underlying connection, when the session was created by the Bedrock client or server handshake.
    /// </summary>
    public ConnectionContext Connection { get; }

    /// <summary>
    /// Whether this endpoint is the server side of the session.
    /// </summary>
    public bool IsServer => _isServer;

    /// <summary>
    /// The negotiated subprotocol, or null.
    /// </summary>
    public string SubProtocol { get; }

    /// <summary>
    /// The negotiated permessage-deflate parameters, or null if compression is not in use.
    /// </summary>
    public PerMessageDeflateParameters Compression { get; }

    /// <summary>
    /// The close status sent by the peer, or the status this endpoint failed the connection with.
    /// </summary>
    public WebSocketCloseStatus? CloseStatus => _closeStatus;

    /// <summary>
    /// The close reason that accompanies <see cref="CloseStatus"/>.
    /// </summary>
    public string CloseStatusDescription => _closeStatusDescription;

    /// <summary>
    /// The current state of the session.
    /// </summary>
    public WebSocketState State =>
        _aborted ? WebSocketState.Aborted :
        _closeSent && _closeReceived ? WebSocketState.Closed :
        _closeSent ? WebSocketState.CloseSent :
        _closeReceived ? WebSocketState.CloseReceived :
        WebSocketState.Open;

    #region Receiving

    /// <summary>
    /// Reads a complete message, buffering all of its frames. Close messages are returned with <see cref="WebSocketMessageType.Close"/>.
    /// </summary>
    public async ValueTask<WebSocketMessage> ReadMessageAsync(CancellationToken cancellationToken = default)
    {
        var buffer = new ArrayBufferWriter<byte>();
        while (true)
        {
            var result = await ReadAsync(buffer.GetMemory(4096), cancellationToken).ConfigureAwait(false);
            if (result.MessageType == WebSocketMessageType.Close)
            {
                return new WebSocketMessage(WebSocketMessageType.Close, ReadOnlyMemory<byte>.Empty, result.CloseStatus, result.CloseStatusDescription);
            }

            buffer.Advance(result.Count);
            if (result.EndOfMessage)
            {
                return new WebSocketMessage(result.MessageType, buffer.WrittenMemory);
            }
        }
    }

    /// <summary>
    /// Reads the next part of the current message into <paramref name="buffer"/>, processing any control frames on the way.
    /// </summary>
    /// <exception cref="WebSocketException">The peer violated the protocol (the connection is failed with the appropriate
    /// close status first), closed the transport without a close handshake, or the session was aborted.</exception>
    public ValueTask<WebSocketReadResult> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (Interlocked.Exchange(ref _readInProgress, 1) == 1)
        {
            throw new InvalidOperationException("A read is already in progress. Only one read may be outstanding at a time.");
        }

        return ReadWithGuardAsync(buffer, cancellationToken);
    }

    private async ValueTask<WebSocketReadResult> ReadWithGuardAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        try
        {
            return await ReadCoreAsync(buffer, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            Volatile.Write(ref _readInProgress, 0);
        }
    }

    private async ValueTask<WebSocketReadResult> ReadCoreAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        ThrowIfAborted();

        if (_closeReceived)
        {
            return CloseResult();
        }

        if (_inflatedCount > 0 || _inflatedEndsMessage)
        {
            return ServeInflated(buffer.Span);
        }

        while (true)
        {
            ReadResult result;
            try
            {
                result = await _input.ReadAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Abort();
                throw new WebSocketException(WebSocketError.ConnectionClosedPrematurely, "The transport failed while reading.", ex);
            }

            if (result.IsCanceled)
            {
                ThrowIfAborted();
                throw new OperationCanceledException(cancellationToken);
            }

            var step = Process(result.Buffer, buffer.Span, out var consumed, out var examined);
            _input.AdvanceTo(consumed, examined);

            switch (step.Kind)
            {
                case StepKind.Data:
                    return step.Result;

                case StepKind.Inflated:
                    return ServeInflated(buffer.Span);

                case StepKind.Control:
                    Volatile.Write(ref _lastReceiveTimestamp, Environment.TickCount64);
                    if (await HandleControlFrameAsync(step.Header, step.ControlPayload).ConfigureAwait(false))
                    {
                        return CloseResult();
                    }
                    continue;

                case StepKind.Error:
                    await FailAsync(step.ErrorStatus, step.ErrorMessage).ConfigureAwait(false);
                    break;

                case StepKind.NeedMore:
                    if (result.IsCompleted)
                    {
                        Abort();
                        throw new WebSocketException(WebSocketError.ConnectionClosedPrematurely, "The remote party closed the connection without completing the close handshake.");
                    }
                    continue;
            }
        }
    }

    private enum StepKind { NeedMore, Data, Inflated, Control, Error }

    private readonly struct Step
    {
        public StepKind Kind { get; init; }
        public WebSocketReadResult Result { get; init; }
        public WebSocketHeader Header { get; init; }
        public byte[] ControlPayload { get; init; }
        public WebSocketCloseStatus ErrorStatus { get; init; }
        public string ErrorMessage { get; init; }

        public static Step NeedMore => new() { Kind = StepKind.NeedMore };
        public static Step Inflated => new() { Kind = StepKind.Inflated };
        public static Step Data(WebSocketReadResult result) => new() { Kind = StepKind.Data, Result = result };
        public static Step Control(WebSocketHeader header, byte[] payload) => new() { Kind = StepKind.Control, Header = header, ControlPayload = payload };
        public static Step Error(WebSocketCloseStatus status, string message) => new() { Kind = StepKind.Error, ErrorStatus = status, ErrorMessage = message };
    }

    /// <summary>
    /// Synchronously processes as much buffered input as is needed to produce one result.
    /// </summary>
    private Step Process(in ReadOnlySequence<byte> buffer, Span<byte> destination, out SequencePosition consumed, out SequencePosition examined)
    {
        consumed = buffer.Start;
        examined = buffer.End;
        var remaining = buffer;

        if (!remaining.IsEmpty)
        {
            Volatile.Write(ref _lastReceiveTimestamp, Environment.TickCount64);
        }

        while (true)
        {
            if (!_inFrame)
            {
                if (remaining.IsEmpty)
                {
                    return Step.NeedMore;
                }

                SequencePosition headerEnd = default, headerExamined = default;
                WebSocketReadFrame frame;
                try
                {
                    if (!new WebSocketFrameReader().TryParseMessage(remaining, ref headerEnd, ref headerExamined, out frame))
                    {
                        return Step.NeedMore;
                    }
                }
                catch (WebSocketFrameException ex)
                {
                    return Step.Error(WebSocketCloseStatus.ProtocolError, ex.Message);
                }

                var header = frame.Header;
                var error = ValidateHeader(header);
                if (error != null)
                {
                    return Step.Error(WebSocketCloseStatus.ProtocolError, error);
                }

                var afterHeader = remaining.Slice(headerEnd);

                if (header.IsControlFrame)
                {
                    var length = (int)header.PayloadLength;
                    if (afterHeader.Length < length)
                    {
                        // Leave the header unconsumed until the whole (small) control payload has arrived
                        return Step.NeedMore;
                    }

                    var payload = afterHeader.Slice(0, length).ToArray();
                    if (header.Masked)
                    {
                        new WebSocketPayloadEncoder(header.MaskingKey).MaskUnmask(payload);
                    }

                    consumed = afterHeader.GetPosition(length);
                    examined = consumed;
                    return Step.Control(header, payload);
                }

                if (header.Opcode != WebSocketOpcode.Continuation)
                {
                    _inMessage = true;
                    _messageType = header.Opcode == WebSocketOpcode.Text ? WebSocketMessageType.Text : WebSocketMessageType.Binary;
                    _messageCompressed = header.Rsv1;
                    _messageLength = 0;
                    _utf8.Reset();
                }

                if (!_messageCompressed && _maxMessageSize is long max && (ulong)_messageLength + header.PayloadLength > (ulong)max)
                {
                    return Step.Error(WebSocketCloseStatus.MessageTooBig, $"The message exceeds the maximum allowed size of {max} bytes.");
                }

                _inFrame = true;
                _frameHeader = header;
                _frameRemaining = header.PayloadLength;
                _frameEncoder = new WebSocketPayloadEncoder(header.MaskingKey);

                remaining = afterHeader;
                consumed = remaining.Start;
            }

            var fin = _frameHeader.Fin;

            if (_messageCompressed)
            {
                if (_frameRemaining > 0)
                {
                    if (remaining.IsEmpty)
                    {
                        return Step.NeedMore;
                    }

                    var take = (long)Math.Min(_frameRemaining, (ulong)remaining.Length);
                    foreach (var segment in remaining.Slice(0, take))
                    {
                        if (_frameHeader.Masked)
                        {
                            _inflater.Push(segment.Span, ref _frameEncoder);
                        }
                        else
                        {
                            _inflater.Push(segment.Span);
                        }
                    }

                    _frameRemaining -= (ulong)take;
                    remaining = remaining.Slice(take);
                    consumed = remaining.Start;
                }

                var endOfInput = false;
                if (_frameRemaining == 0)
                {
                    _inFrame = false;
                    if (fin)
                    {
                        _inflater.EndMessage();
                        endOfInput = true;
                    }
                }

                var drainError = DrainInflater(endOfInput);
                if (drainError.Kind == StepKind.Error)
                {
                    return drainError;
                }

                if (_inflatedCount > 0 || _inflatedEndsMessage)
                {
                    examined = consumed;
                    return Step.Inflated;
                }

                if (_inFrame)
                {
                    return Step.NeedMore;
                }

                continue;
            }

            if (_frameRemaining == 0)
            {
                _inFrame = false;
                if (!fin)
                {
                    continue;
                }

                if (_messageType == WebSocketMessageType.Text && !_utf8.TryValidate(ReadOnlySpan<byte>.Empty, endOfMessage: true))
                {
                    return Step.Error(WebSocketCloseStatus.InvalidPayloadData, "The text message is not valid UTF-8.");
                }

                _inMessage = false;
                examined = consumed;
                return Step.Data(new WebSocketReadResult(0, _messageType, endOfMessage: true));
            }

            if (remaining.IsEmpty)
            {
                return Step.NeedMore;
            }

            if (destination.IsEmpty)
            {
                examined = consumed;
                return Step.Data(new WebSocketReadResult(0, _messageType, endOfMessage: false));
            }

            var count = (int)Math.Min(Math.Min(_frameRemaining, (ulong)remaining.Length), (ulong)destination.Length);
            var output = destination[..count];
            remaining.Slice(0, count).CopyTo(output);
            if (_frameHeader.Masked)
            {
                _frameEncoder.MaskUnmask(output);
            }

            _frameRemaining -= (ulong)count;
            _messageLength += count;
            consumed = remaining.GetPosition(count);
            examined = consumed;

            var endOfMessage = fin && _frameRemaining == 0;
            if (_frameRemaining == 0)
            {
                _inFrame = false;
            }

            if (_messageType == WebSocketMessageType.Text && !_utf8.TryValidate(output, endOfMessage))
            {
                return Step.Error(WebSocketCloseStatus.InvalidPayloadData, "The text message is not valid UTF-8.");
            }

            if (endOfMessage)
            {
                _inMessage = false;
            }

            return Step.Data(new WebSocketReadResult(count, _messageType, endOfMessage));
        }
    }

    private string ValidateHeader(in WebSocketHeader header)
    {
        // RFC 6455 5.1: clients must mask, servers must not
        if (_isServer && !header.Masked)
        {
            return "Received an unmasked frame from the client.";
        }

        if (!_isServer && header.Masked)
        {
            return "Received a masked frame from the server.";
        }

        // RFC 6455 5.2: reserved bits must be zero unless an extension defines them
        if (header.Rsv2 || header.Rsv3)
        {
            return "Received a frame with RSV2 or RSV3 set, but no extension defining them was negotiated.";
        }

        if (header.Rsv1)
        {
            if (_inflater == null)
            {
                return "Received a frame with RSV1 set, but permessage-deflate was not negotiated.";
            }

            // RFC 7692 6: only the first frame of a data message may set RSV1
            if (header.IsControlFrame || header.Opcode == WebSocketOpcode.Continuation)
            {
                return "RSV1 may only be set on the first frame of a data message.";
            }
        }

        if (header.IsControlFrame)
        {
            return null;
        }

        // RFC 6455 5.4: fragmentation sequencing
        if (header.Opcode == WebSocketOpcode.Continuation && !_inMessage)
        {
            return "Received a continuation frame without a message in progress.";
        }

        if (header.Opcode != WebSocketOpcode.Continuation && _inMessage)
        {
            return "Received a new data frame while the previous message was still in progress.";
        }

        return null;
    }

    private Step DrainInflater(bool endOfInput)
    {
        _inflated ??= new byte[16 * 1024];

        while (true)
        {
            // Compact or grow so there is always room to inflate into
            if (_inflatedCount == 0)
            {
                _inflatedOffset = 0;
            }

            var free = _inflated.Length - (_inflatedOffset + _inflatedCount);
            if (free < 4096)
            {
                if (_inflatedOffset > 0)
                {
                    Buffer.BlockCopy(_inflated, _inflatedOffset, _inflated, 0, _inflatedCount);
                    _inflatedOffset = 0;
                }

                if (_inflated.Length - _inflatedCount < 4096)
                {
                    Array.Resize(ref _inflated, _inflated.Length * 2);
                }
            }

            var target = _inflated.AsSpan(_inflatedOffset + _inflatedCount);

            int written;
            try
            {
                written = _inflater.Inflate(target);
            }
            catch (WebSocketCompressionException ex)
            {
                return Step.Error(WebSocketCloseStatus.InvalidPayloadData, ex.Message);
            }

            if (written == 0)
            {
                break;
            }

            _messageLength += written;
            if (_maxMessageSize is long max && _messageLength > max)
            {
                return Step.Error(WebSocketCloseStatus.MessageTooBig, $"The decompressed message exceeds the maximum allowed size of {max} bytes.");
            }

            if (_messageType == WebSocketMessageType.Text && !_utf8.TryValidate(target[..written], endOfMessage: false))
            {
                return Step.Error(WebSocketCloseStatus.InvalidPayloadData, "The text message is not valid UTF-8.");
            }

            _inflatedCount += written;
        }

        if (endOfInput)
        {
            if (_messageType == WebSocketMessageType.Text && !_utf8.TryValidate(ReadOnlySpan<byte>.Empty, endOfMessage: true))
            {
                return Step.Error(WebSocketCloseStatus.InvalidPayloadData, "The text message is not valid UTF-8.");
            }

            _inflatedEndsMessage = true;
            _inflater.Reset();
        }

        return default;
    }

    private WebSocketReadResult ServeInflated(Span<byte> destination)
    {
        var count = Math.Min(destination.Length, _inflatedCount);
        _inflated.AsSpan(_inflatedOffset, count).CopyTo(destination);
        _inflatedOffset += count;
        _inflatedCount -= count;

        var endOfMessage = _inflatedCount == 0 && _inflatedEndsMessage;
        if (endOfMessage)
        {
            _inflatedEndsMessage = false;
            _inMessage = false;
        }

        if (_inflatedCount == 0)
        {
            _inflatedOffset = 0;
        }

        return new WebSocketReadResult(count, _messageType, endOfMessage);
    }

    /// <summary>
    /// Handles a received control frame.
    /// </summary>
    /// <returns>True if the frame was a Close frame.</returns>
    private async ValueTask<bool> HandleControlFrameAsync(WebSocketHeader header, byte[] payload)
    {
        switch (header.Opcode)
        {
            case WebSocketOpcode.Ping:
                if (!_closeSent)
                {
                    try
                    {
                        await SendControlFrameAsync(WebSocketOpcode.Pong, payload, CancellationToken.None).ConfigureAwait(false);
                    }
                    catch (WebSocketException) when (_closeSent)
                    {
                        // Raced with a close; a Pong is no longer required
                    }
                }
                return false;

            case WebSocketOpcode.Pong:
                return false;

            case WebSocketOpcode.Close:
                await HandleCloseFrameAsync(payload).ConfigureAwait(false);
                return true;

            default:
                return false;
        }
    }

    private async ValueTask HandleCloseFrameAsync(byte[] payload)
    {
        WebSocketCloseStatus? status = null;
        string description = null;

        if (payload.Length == 1)
        {
            await FailAsync(WebSocketCloseStatus.ProtocolError, "Received a Close frame with a 1 byte payload.").ConfigureAwait(false);
        }

        if (payload.Length >= 2)
        {
            var code = BinaryPrimitives.ReadUInt16BigEndian(payload);
            if (!IsValidReceivedCloseStatus(code))
            {
                await FailAsync(WebSocketCloseStatus.ProtocolError, $"Received a Close frame with invalid status code {code}.").ConfigureAwait(false);
            }

            if (!Utf8.IsValid(payload.AsSpan(2)))
            {
                await FailAsync(WebSocketCloseStatus.InvalidPayloadData, "Received a Close frame whose reason is not valid UTF-8.").ConfigureAwait(false);
            }

            status = (WebSocketCloseStatus)code;
            description = Encoding.UTF8.GetString(payload, 2, payload.Length - 2);
        }

        _closeStatus = status ?? WebSocketCloseStatus.Empty;
        _closeStatusDescription = description ?? string.Empty;
        _closeReceived = true;

        if (!_closeSent)
        {
            // RFC 6455 5.5.1: respond with a Close frame, echoing the status code
            try
            {
                await SendCloseFrameAsync(status, null, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception) when (_closeSent || _aborted)
            {
            }
            catch (Exception)
            {
                // The peer may already have gone away; the close handshake is still complete from our side
            }
        }

        await CompleteOutputAsync().ConfigureAwait(false);
        _closeReceivedTcs.TrySetResult();
    }

    private WebSocketReadResult CloseResult() =>
        new(0, WebSocketMessageType.Close, endOfMessage: true, _closeStatus, _closeStatusDescription);

    /// <summary>
    /// Fails the WebSocket connection (RFC 6455 section 7.1.7): sends a Close frame with the status if possible, then aborts.
    /// </summary>
    private async ValueTask FailAsync(WebSocketCloseStatus status, string message)
    {
        _closeStatus = status;
        _closeStatusDescription = message;

        if (!_closeSent && !_aborted)
        {
            try
            {
                using var timeout = new CancellationTokenSource(_options.CloseTimeout);
                await SendCloseFrameAsync(status, null, timeout.Token).ConfigureAwait(false);
            }
            catch
            {
                // Best effort
            }
        }

        Abort();
        throw new WebSocketException(WebSocketError.Faulted, $"The WebSocket connection was failed with status {(int)status} ({status}): {message}");
    }

    private static bool IsValidReceivedCloseStatus(int code) =>
        code is (>= 1000 and <= 1003) or (>= 1007 and <= 1014) or (>= 3000 and <= 4999);

    #endregion

    #region Sending

    /// <summary>
    /// Sends a complete text message.
    /// </summary>
    public ValueTask SendTextAsync(string text, CancellationToken cancellationToken = default)
        => SendAsync(Encoding.UTF8.GetBytes(text), WebSocketMessageType.Text, endOfMessage: true, cancellationToken);

    /// <summary>
    /// Sends a message, or part of one. While a message is in progress (the previous call passed endOfMessage: false)
    /// further calls continue that message.
    /// </summary>
    public ValueTask SendAsync(ReadOnlySequence<byte> data, WebSocketMessageType messageType, bool endOfMessage = true, CancellationToken cancellationToken = default)
    {
        if (data.IsSingleSegment)
        {
            return SendAsync(data.First, messageType, endOfMessage, cancellationToken);
        }

        return SendAsync(data.ToArray(), messageType, endOfMessage, cancellationToken);
    }

    /// <summary>
    /// Sends a message, or part of one. While a message is in progress (the previous call passed endOfMessage: false)
    /// further calls continue that message.
    /// </summary>
    public async ValueTask SendAsync(ReadOnlyMemory<byte> data, WebSocketMessageType messageType, bool endOfMessage = true, CancellationToken cancellationToken = default)
    {
        if (messageType == WebSocketMessageType.Close)
        {
            throw new ArgumentException("Use CloseAsync or CloseOutputAsync to close the session.", nameof(messageType));
        }

        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfCannotSend();

            var opcode = _sendInMessage
                ? WebSocketOpcode.Continuation
                : messageType == WebSocketMessageType.Text ? WebSocketOpcode.Text : WebSocketOpcode.Binary;

            var rsv1 = false;
            if (!_sendInMessage)
            {
                _sendCompressed = _deflater != null && !(endOfMessage && data.Length < _minimumCompressedMessageSize);
                rsv1 = _sendCompressed;
            }

            var payload = _sendCompressed ? _deflater.Compress(data.Span, endOfMessage) : data;

            WriteFrame(opcode, endOfMessage, rsv1, payload);
            _sendInMessage = !endOfMessage;

            await FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>
    /// Sends a Ping frame with an optional payload of at most 125 bytes.
    /// </summary>
    public ValueTask PingAsync(ReadOnlyMemory<byte> payload = default, CancellationToken cancellationToken = default)
        => SendControlFrameAsync(WebSocketOpcode.Ping, payload, cancellationToken);

    /// <summary>
    /// Sends an unsolicited Pong frame (RFC 6455 5.5.3), which can serve as a unidirectional heartbeat.
    /// </summary>
    public ValueTask PongAsync(ReadOnlyMemory<byte> payload = default, CancellationToken cancellationToken = default)
        => SendControlFrameAsync(WebSocketOpcode.Pong, payload, cancellationToken);

    private async ValueTask SendControlFrameAsync(WebSocketOpcode opcode, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        if (payload.Length > MaxControlPayload)
        {
            throw new ArgumentOutOfRangeException(nameof(payload), $"Control frame payloads must be {MaxControlPayload} bytes or less.");
        }

        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfCannotSend();
            WriteFrame(opcode, fin: true, rsv1: false, payload);
            await FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async ValueTask SendCloseFrameAsync(WebSocketCloseStatus? status, string description, CancellationToken cancellationToken)
    {
        byte[] payload;
        if (status is null || status == WebSocketCloseStatus.Empty)
        {
            payload = [];
        }
        else
        {
            var reason = Encoding.UTF8.GetBytes(description ?? string.Empty);
            payload = new byte[2 + reason.Length];
            BinaryPrimitives.WriteUInt16BigEndian(payload, (ushort)status.Value);
            reason.CopyTo(payload, 2);
        }

        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_closeSent)
            {
                return;
            }

            ThrowIfAborted();
            WriteFrame(WebSocketOpcode.Close, fin: true, rsv1: false, payload);
            _closeSent = true;
            await FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private void WriteFrame(WebSocketOpcode opcode, bool fin, bool rsv1, ReadOnlyMemory<byte> payload)
    {
        var length = (ulong)payload.Length;
        var header = _isServer
            ? new WebSocketHeader(fin, opcode, masked: false, length, maskingKey: 0, rsv1, rsv2: false, rsv3: false)
            : new WebSocketHeader(fin, opcode, masked: true, length, WebSocketHeader.GenerateMaskingKey(), rsv1, rsv2: false, rsv3: false);

        _frameWriter.WriteMessage(new WebSocketWriteFrame(header, new ReadOnlySequence<byte>(payload)), _output);
    }

    private async ValueTask FlushAsync(CancellationToken cancellationToken)
    {
        FlushResult result;
        try
        {
            result = await _output.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Abort();
            throw new WebSocketException(WebSocketError.ConnectionClosedPrematurely, "The transport failed while writing.", ex);
        }

        if (result.IsCanceled)
        {
            ThrowIfAborted();
            throw new OperationCanceledException(cancellationToken);
        }
    }

    private void ThrowIfCannotSend()
    {
        ThrowIfAborted();
        if (_closeSent)
        {
            throw new WebSocketException(WebSocketError.InvalidState, "A Close frame has already been sent; no further frames may be sent.");
        }
    }

    private void ThrowIfAborted()
    {
        if (_aborted)
        {
            throw new WebSocketException(WebSocketError.InvalidState, "The WebSocket session has been aborted.");
        }

        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(WebSocketSession));
        }
    }

    #endregion

    #region Closing

    /// <summary>
    /// Performs the close handshake: sends a Close frame (if not already sent) and waits for the peer's Close frame,
    /// discarding any data messages that arrive meanwhile. Aborts if the peer does not respond within <see cref="WebSocketSessionOptions.CloseTimeout"/>.
    /// </summary>
    /// <remarks>
    /// If another read is in progress (for example a receive loop), this waits for that loop to observe the peer's Close frame.
    /// </remarks>
    public async ValueTask CloseAsync(WebSocketCloseStatus closeStatus, string statusDescription = null, CancellationToken cancellationToken = default)
    {
        if (State is WebSocketState.Closed or WebSocketState.Aborted)
        {
            return;
        }

        await CloseOutputAsync(closeStatus, statusDescription, cancellationToken).ConfigureAwait(false);

        if (_closeReceived)
        {
            return;
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.CloseTimeout);

        try
        {
            if (Volatile.Read(ref _readInProgress) == 1)
            {
                await _closeReceivedTcs.Task.WaitAsync(timeout.Token).ConfigureAwait(false);
                return;
            }

            var scratch = new byte[4096];
            while (!_closeReceived)
            {
                var result = await ReadAsync(scratch, timeout.Token).ConfigureAwait(false);
                if (result.MessageType == WebSocketMessageType.Close)
                {
                    break;
                }
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // The peer did not complete the close handshake in time
            Abort();
        }
        catch (WebSocketException)
        {
            // The connection failed or was closed while waiting; the session is now aborted
        }
    }

    /// <summary>
    /// Sends a Close frame without waiting for the peer's response. No further messages may be sent afterwards.
    /// </summary>
    public async ValueTask CloseOutputAsync(WebSocketCloseStatus closeStatus, string statusDescription = null, CancellationToken cancellationToken = default)
    {
        ValidateCloseStatus(closeStatus, statusDescription);

        if (_closeSent)
        {
            return;
        }

        await SendCloseFrameAsync(closeStatus, statusDescription, cancellationToken).ConfigureAwait(false);

        if (_closeReceived)
        {
            await CompleteOutputAsync().ConfigureAwait(false);
        }
    }

    private static void ValidateCloseStatus(WebSocketCloseStatus status, string description)
    {
        var code = (int)status;
        if (status == WebSocketCloseStatus.Empty)
        {
            if (!string.IsNullOrEmpty(description))
            {
                throw new ArgumentException("A close description cannot be sent without a close status.", nameof(description));
            }
            return;
        }

        if (!IsValidReceivedCloseStatus(code))
        {
            throw new ArgumentOutOfRangeException(nameof(status), $"{code} is not a close status code that may be sent.");
        }

        if (description != null && Encoding.UTF8.GetByteCount(description) > MaxControlPayload - 2)
        {
            throw new ArgumentException($"The close description must be at most {MaxControlPayload - 2} bytes of UTF-8.", nameof(description));
        }
    }

    private async ValueTask CompleteOutputAsync()
    {
        await _writeLock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (!_outputCompleted)
            {
                _outputCompleted = true;
                await _output.CompleteAsync().ConfigureAwait(false);
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>
    /// Immediately aborts the session without a close handshake. Pending reads and writes fail.
    /// </summary>
    public void Abort()
    {
        if (_aborted || State == WebSocketState.Closed)
        {
            return;
        }

        _aborted = true;
        _abortCts.Cancel();
        _input.CancelPendingRead();
        _output.CancelPendingFlush();
        Connection?.Abort(new ConnectionAbortedException("The WebSocket session was aborted."));
        _closeReceivedTcs.TrySetResult();
    }

    /// <summary>
    /// Aborts the session if it has not been closed, and releases its resources.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        if (State != WebSocketState.Closed)
        {
            Abort();
        }

        _abortCts.Cancel();
        try
        {
            await _keepAliveTask.ConfigureAwait(false);
        }
        catch
        {
        }

        _disposed = true;

        await CompleteOutputAsync().ConfigureAwait(false);

        // Only complete the input if no read is running; a running read will fail on the cancelled read instead
        if (Volatile.Read(ref _readInProgress) == 0)
        {
            await _input.CompleteAsync().ConfigureAwait(false);
        }

        _deflater?.Dispose();
        _inflater?.Dispose();
        _abortCts.Dispose();

        if (_owner != null)
        {
            await _owner.DisposeAsync().ConfigureAwait(false);
        }
    }

    #endregion

    #region Keep-alive

    private async Task KeepAliveLoopAsync(TimeSpan interval, TimeSpan timeout)
    {
        // Yield so construction is never blocked by the loop
        await Task.Yield();

        var token = _abortCts.Token;
        long counter = 0;
        var payload = new byte[sizeof(long)];

        try
        {
            while (true)
            {
                await Task.Delay(interval, token).ConfigureAwait(false);

                if (State != WebSocketState.Open)
                {
                    return;
                }

                var sentAt = Environment.TickCount64;
                BinaryPrimitives.WriteInt64BigEndian(payload, ++counter);
                await PingAsync(payload, token).ConfigureAwait(false);

                if (timeout > TimeSpan.Zero && timeout != Timeout.InfiniteTimeSpan)
                {
                    await Task.Delay(timeout, token).ConfigureAwait(false);
                    if (Volatile.Read(ref _lastReceiveTimestamp) < sentAt && State == WebSocketState.Open)
                    {
                        _closeStatus = WebSocketCloseStatus.EndpointUnavailable;
                        _closeStatusDescription = "The peer did not respond to a keep-alive ping in time.";
                        Abort();
                        return;
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (WebSocketException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    #endregion
}
