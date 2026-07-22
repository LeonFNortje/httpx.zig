//! TLS/SSL Support for httpx.zig
//!
//! Provides TLS configuration and a session wrapper for HTTPS connections.
//!
//! ## Backend
//!
//! This wrapper is backed by the vendored `ianic/tls.zig` library (see
//! `src/tls/tlszig/VENDOR.md`), consumed as the `tls` module. Unlike
//! `std.crypto.tls.Client`, tls.zig advertises ALPN protocols in the ClientHello
//! and exposes the negotiated protocol after the handshake. That negotiated value
//! is stored in `TlsSession.negotiated_protocol`, which the HTTP client reads to
//! route between the HTTP/2 and HTTP/1.1 code paths over the same TLS session.
//!
//! ## Notes
//!
//! - `handshake()` advertises `config.alpn_protocols` and records the negotiated
//!   protocol (or leaves it null when the server does not select one).
//! - The high-level HTTP/3 runtime path uses UDP + QUIC framing primitives and
//!   does not go through this TLS wrapper.

const std = @import("std");
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");
const tlsz = @import("tls");
const Socket = @import("../net/socket.zig").Socket;
const SocketIoReader = @import("../net/socket.zig").SocketIoReader;
const SocketIoWriter = @import("../net/socket.zig").SocketIoWriter;
const io_util = @import("../util/any_io.zig");
const defaultIo = io_util.defaultIo;

/// Minimum TLS version configuration.
pub const TlsVersion = enum {
    tls_1_0,
    tls_1_1,
    tls_1_2,
    tls_1_3,

    pub fn toString(self: TlsVersion) []const u8 {
        return switch (self) {
            .tls_1_0 => "TLSv1.0",
            .tls_1_1 => "TLSv1.1",
            .tls_1_2 => "TLSv1.2",
            .tls_1_3 => "TLSv1.3",
        };
    }
};

/// TLS verification mode.
pub const VerifyMode = enum {
    none,
    peer,
    fail_if_no_peer_cert,
    client_once,
};

/// TLS configuration for clients and servers.
pub const TlsConfig = struct {
    allocator: Allocator,
    min_version: TlsVersion = .tls_1_2,
    max_version: TlsVersion = .tls_1_3,
    verify_mode: VerifyMode = .peer,
    verify_hostname: bool = true,
    /// Whether a peer that closes the transport without sending a TLS
    /// close_notify alert is treated as a clean EOF (true) or surfaced as a
    /// truncation error (false). Defaults to true to preserve the historical
    /// behavior of this wrapper.
    allow_truncation_attacks: bool = true,
    ca_file: ?[]const u8 = null,
    ca_path: ?[]const u8 = null,
    cert_file: ?[]const u8 = null,
    key_file: ?[]const u8 = null,
    /// ALPN protocols advertised in the ClientHello. The server selects one; the
    /// choice is surfaced via `TlsSession.negotiated_protocol`. Defaults to
    /// HTTP/1.1-only so callers that do not opt into HTTP/2 keep the previous
    /// behavior. The HTTP client sets `{"h2","http/1.1"}` for request paths that
    /// can use HTTP/2.
    alpn_protocols: []const []const u8 = &.{"http/1.1"},
    cipher_suites: ?[]const u8 = null,
    server_name: ?[]const u8 = null,

    const Self = @This();

    /// Creates a default TLS configuration.
    pub fn init(allocator: Allocator) Self {
        return .{ .allocator = allocator };
    }

    /// Creates a configuration that skips certificate verification.
    pub fn insecure(allocator: Allocator) Self {
        var config = init(allocator);
        config.verify_mode = .none;
        config.verify_hostname = false;
        return config;
    }

    /// Sets the CA certificate file.
    pub fn setCaFile(self: *Self, path: []const u8) void {
        self.ca_file = path;
    }

    /// Sets the client certificate and key files.
    pub fn setClientCert(self: *Self, cert_file: []const u8, key_file: []const u8) void {
        self.cert_file = cert_file;
        self.key_file = key_file;
    }

    /// Sets the server name for SNI.
    pub fn setServerName(self: *Self, name: []const u8) void {
        self.server_name = name;
    }

    /// Creates a copy of the configuration.
    pub fn clone(self: *const Self) Self {
        return self.*;
    }
};

/// TLS session state.
///
/// Heap-pinning invariant: after `handshake()`, the tls.zig `Connection` holds
/// pointers into this struct's socket reader/writer, and the cached
/// `Reader`/`Writer` hold a pointer back into `conn`. Do not move a `TlsSession`
/// (or copy it by value) after the handshake — keep it pinned for its lifetime.
pub const TlsSession = struct {
    allocator: Allocator,
    config: TlsConfig,
    negotiated_protocol: ?[]const u8 = null,
    peer_certificate: ?[]const u8 = null,
    connected: bool = false,
    socket: ?*Socket = null,

    // Socket-side (ciphertext) buffers and the Io reader/writer over the socket.
    net_read_buf: ?[]u8 = null,
    net_write_buf: ?[]u8 = null,
    net_in: ?SocketIoReader = null,
    net_out: ?SocketIoWriter = null,

    // Application-side (cleartext) buffers backing the Io.Reader/Io.Writer that
    // the HTTP/1.1 path reads and writes through.
    app_read_buf: ?[]u8 = null,
    app_write_buf: ?[]u8 = null,

    ca_bundle: ?std.crypto.Certificate.Bundle = null,
    conn: ?tlsz.Connection = null,
    tls_reader: ?tlsz.Connection.Reader = null,
    tls_writer: ?tlsz.Connection.Writer = null,

    const Self = @This();

    /// Creates a new TLS session with the given configuration.
    pub fn init(config: TlsConfig) Self {
        return .{
            .allocator = config.allocator,
            .config = config,
        };
    }

    /// Releases session resources.
    pub fn deinit(self: *Self) void {
        self.conn = null;
        self.tls_reader = null;
        self.tls_writer = null;

        if (self.ca_bundle) |*bundle| {
            bundle.deinit(self.allocator);
            self.ca_bundle = null;
        }

        if (self.net_read_buf) |buf| self.allocator.free(buf);
        if (self.net_write_buf) |buf| self.allocator.free(buf);
        if (self.app_read_buf) |buf| self.allocator.free(buf);
        if (self.app_write_buf) |buf| self.allocator.free(buf);

        self.net_read_buf = null;
        self.net_write_buf = null;
        self.app_read_buf = null;
        self.app_write_buf = null;
        self.net_in = null;
        self.net_out = null;
    }

    /// Attaches a connected socket that will carry the TLS session.
    pub fn attachSocket(self: *Self, socket: *Socket) void {
        self.socket = socket;
    }

    /// Performs the TLS handshake.
    ///
    /// The protocols in `config.alpn_protocols` are advertised in the ClientHello.
    /// After a successful handshake the negotiated protocol (if any) is stored in
    /// `self.negotiated_protocol` for the HTTP client to route on.
    pub fn handshake(self: *Self, hostname: []const u8) !void {
        const sock = self.socket orelse return error.MissingTransport;

        // Socket-side buffers. tls.zig needs the input reader buffer to hold a
        // full TLS record (input_buffer_len) and the output writer buffer to hold
        // a ClientHello / one encrypted record (output_buffer_len).
        const net_in_len: usize = @max(16 * 1024, tlsz.input_buffer_len);
        const net_out_len: usize = @max(16 * 1024, tlsz.output_buffer_len);
        if (self.net_read_buf == null) self.net_read_buf = try self.allocator.alloc(u8, net_in_len);
        if (self.net_write_buf == null) self.net_write_buf = try self.allocator.alloc(u8, net_out_len);

        // Cleartext buffers for the HTTP/1.1 Io.Reader/Io.Writer.
        if (self.app_read_buf == null) self.app_read_buf = try self.allocator.alloc(u8, 16 * 1024);
        if (self.app_write_buf == null) self.app_write_buf = try self.allocator.alloc(u8, 16 * 1024);

        self.net_in = SocketIoReader.init(sock, self.net_read_buf.?);
        self.net_out = SocketIoWriter.init(sock, self.net_write_buf.?);
        const io = defaultIo();

        const verify = self.config.verify_mode != .none;

        // System CA bundle (cross-platform); only needed when verifying.
        if (verify) {
            var bundle: std.crypto.Certificate.Bundle = .empty;
            errdefer bundle.deinit(self.allocator);
            try bundle.rescan(self.allocator, io, std.Io.Timestamp.now(io, .real));
            self.ca_bundle = bundle;
        }

        const sni_host = self.config.server_name orelse hostname;
        var rng_impl: std.Random.IoSource = .{ .io = io };

        const conn = try tlsz.client(&self.net_in.?.reader, &self.net_out.?.writer, .{
            .host = sni_host,
            .root_ca = self.ca_bundle orelse .empty,
            // tls.zig couples chain and hostname verification under one flag.
            .insecure_skip_verify = !verify,
            .alpn_protocols = self.config.alpn_protocols,
            .now = std.Io.Timestamp.now(io, .real),
            .rng = rng_impl.interface(),
        });

        self.conn = conn;
        self.connected = true;

        // Pin the cleartext Reader/Writer over the stored Connection so the
        // HTTP/1.1 path has stable Io interfaces for its lifetime.
        self.tls_reader = self.conn.?.reader(self.app_read_buf.?);
        self.tls_writer = self.conn.?.writer(self.app_write_buf.?);

        // Surface the negotiated ALPN protocol so the HTTP client routes
        // HTTP/2 vs HTTP/1.1. Null means the server selected nothing → HTTP/1.1.
        self.negotiated_protocol = self.conn.?.alpn_protocol;
    }

    /// Reads decrypted data from the session.
    pub fn read(self: *Self, buffer: []u8) !usize {
        const c = if (self.conn) |*c| c else return error.NotConnected;
        return c.read(buffer);
    }

    /// Writes data to be encrypted and sent. Returns the number of bytes accepted.
    pub fn write(self: *Self, data: []const u8) !usize {
        const c = if (self.conn) |*c| c else return error.NotConnected;
        return c.write(data);
    }

    /// Flushes any buffered cleartext through the TLS layer to the socket.
    pub fn flush(self: *Self) !void {
        if (self.conn == null) return error.NotConnected;
        if (self.tls_writer) |*w| try w.interface.flush();
        if (self.net_out) |*out| try out.writer.flush();
    }

    /// Returns an I/O reader for decrypted TLS payload.
    pub fn getReader(self: *Self) !*std.Io.Reader {
        if (self.tls_reader == null) return error.NotConnected;
        return &self.tls_reader.?.interface;
    }

    /// Returns an I/O writer for TLS-encrypted payload.
    pub fn getWriter(self: *Self) !*std.Io.Writer {
        if (self.tls_writer == null) return error.NotConnected;
        return &self.tls_writer.?.interface;
    }

    /// Returns the negotiated ALPN protocol.
    pub fn getAlpnProtocol(self: *const Self) ?[]const u8 {
        return self.negotiated_protocol;
    }

    /// Returns true if HTTP/2 was negotiated.
    pub fn isHttp2(self: *const Self) bool {
        if (self.negotiated_protocol) |proto| {
            return std.mem.eql(u8, proto, "h2");
        }
        return false;
    }

    /// Returns the peer's certificate in DER format.
    pub fn getPeerCertificate(self: *const Self) ?[]const u8 {
        return self.peer_certificate;
    }

    /// Closes the TLS session.
    pub fn close(self: *Self) void {
        self.connected = false;
        self.conn = null;
        self.tls_reader = null;
        self.tls_writer = null;
    }
};

/// Certificate verification result.
pub const VerifyResult = enum {
    ok,
    expired,
    not_yet_valid,
    revoked,
    hostname_mismatch,
    self_signed,
    invalid_ca,
    invalid_signature,
    unknown_error,
};

/// Parses a PEM-encoded certificate.
pub fn parsePemCertificate(allocator: Allocator, pem_data: []const u8) ![]const u8 {
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";

    const start = std.mem.indexOf(u8, pem_data, begin_marker) orelse return error.InvalidPem;
    const end = std.mem.indexOf(u8, pem_data, end_marker) orelse return error.InvalidPem;

    if (end <= start + begin_marker.len) return error.InvalidPem;

    var base64_block = pem_data[start + begin_marker.len .. end];
    base64_block = std.mem.trim(u8, base64_block, " \t\r\n");

    // Remove all whitespace/newlines from the base64 body.
    var compact = std.ArrayList(u8).empty;
    defer compact.deinit(allocator);
    for (base64_block) |ch| {
        if (ch == '\r' or ch == '\n' or ch == '\t' or ch == ' ') continue;
        try compact.append(allocator, ch);
    }

    const decoder = std.base64.standard.Decoder;
    const out_len = try decoder.calcSizeForSlice(compact.items);
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);
    _ = decoder.decode(out, compact.items) catch return error.InvalidPem;
    return out;
}

/// Returns the system's default CA certificate path.
pub fn getSystemCaPath() ?[]const u8 {
    return switch (builtin.os.tag) {
        .linux => "/etc/ssl/certs/ca-certificates.crt",
        .macos => "/etc/ssl/cert.pem",
        .windows => null,
        .freebsd, .netbsd, .openbsd => "/etc/ssl/cert.pem",
        else => null,
    };
}

test "TlsConfig initialization" {
    const allocator = std.testing.allocator;
    const config = TlsConfig.init(allocator);

    try std.testing.expectEqual(TlsVersion.tls_1_2, config.min_version);
    try std.testing.expectEqual(TlsVersion.tls_1_3, config.max_version);
    try std.testing.expect(config.verify_hostname);
}

test "TlsConfig insecure" {
    const allocator = std.testing.allocator;
    const config = TlsConfig.insecure(allocator);

    try std.testing.expectEqual(VerifyMode.none, config.verify_mode);
    try std.testing.expect(!config.verify_hostname);
}

test "TlsSession initialization" {
    const allocator = std.testing.allocator;
    const config = TlsConfig.init(allocator);
    var session = TlsSession.init(config);
    defer session.deinit();

    try std.testing.expect(!session.connected);
}

test "System CA path" {
    const path = getSystemCaPath();
    if (builtin.os.tag == .linux or builtin.os.tag == .macos) {
        try std.testing.expect(path != null);
    }
}

test "TLS version strings" {
    try std.testing.expectEqualStrings("TLSv1.2", TlsVersion.tls_1_2.toString());
    try std.testing.expectEqualStrings("TLSv1.3", TlsVersion.tls_1_3.toString());
}

test "parsePemCertificate decodes base64 payload" {
    const allocator = std.testing.allocator;
    const pem =
        "-----BEGIN CERTIFICATE-----\n" ++
        "AQID\n" ++
        "-----END CERTIFICATE-----\n";

    const der = try parsePemCertificate(allocator, pem);
    defer allocator.free(der);

    try std.testing.expectEqual(@as(usize, 3), der.len);
    try std.testing.expectEqual(@as(u8, 0x01), der[0]);
    try std.testing.expectEqual(@as(u8, 0x02), der[1]);
    try std.testing.expectEqual(@as(u8, 0x03), der[2]);
}
