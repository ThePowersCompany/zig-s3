/// S3 client implementation.
/// Handles authentication, request signing, and HTTP communication with S3 services.
const std = @import("std");
const Allocator = std.mem.Allocator;
const http = std.http;
const Uri = std.Uri;
const fmt = std.fmt;
const time = std.time;
const tls = std.crypto.tls;
const HttpClient = http.Client;

const lib = @import("../lib.zig");
const signer = @import("auth/signer.zig");
const UtcDateTime = @import("auth/time.zig").UtcDateTime;
const S3Error = lib.S3Error;

/// Configuration for the S3 client.
/// This includes AWS credentials and regional settings.
pub const S3Config = struct {
    /// AWS access key ID or compatible credential
    access_key_id: []const u8,
    /// AWS secret access key or compatible credential
    secret_access_key: []const u8,
    /// AWS region (e.g., "us-east-1")
    region: []const u8 = "us-east-1",
    /// Optional custom endpoint for S3-compatible services (e.g., MinIO, LocalStack)
    endpoint: ?[]const u8 = null,
    /// Path-style URIs follow this format: https://s3.region-code.amazonaws.com/bucket-name/key-name
    /// Virtual-hosted-style URIs follow this format: https://bucket-name.s3.region-code.amazonaws.com/key-name
    /// AWS S3 deprecated path-style URIs in 2020, but other S3-compatible services may still support them.
    path_style: bool = false,

    pub fn bucketUri(self: *const S3Config, alloc: Allocator, bucket_name: []const u8) ![]const u8 {
        const endpoint = if (self.endpoint) |ep| ep else try std.fmt.allocPrint(alloc, "https://s3.{s}.amazonaws.com", .{self.region});
        defer if (self.endpoint == null) alloc.free(endpoint);
        if (endpoint.len == 0) {
            return error.EmptyEndpoint;
        }
        if (self.path_style) {
            var writer: std.io.Writer.Allocating = try .initCapacity(alloc, endpoint.len + 1 + bucket_name.len);
            defer writer.deinit();
            try writer.writer.writeAll(endpoint);
            if (endpoint[endpoint.len - 1] != '/') {
                _ = try writer.writer.write("/");
            }
            _ = try writer.writer.write(bucket_name);
            return try writer.toOwnedSlice();
        } else {
            const uri = try std.Uri.parse(endpoint);
            return try std.fmt.allocPrint(alloc, "{f}//{s}.{f}", .{
                uri.fmt(.{ .scheme = true }),
                bucket_name,
                uri.fmt(.{ .authority = true, .port = true }),
            });
        }
    }
};

/// Main S3 client implementation.
/// Handles low-level HTTP communication and request signing.
pub const S3Client = struct {
    /// Memory allocator used for dynamic allocations
    allocator: Allocator,
    /// Client configuration
    config: S3Config,
    /// HTTP client for making requests
    http_client: HttpClient,

    /// Initialize a new S3 client with the given configuration.
    /// Caller owns the returned client and must call deinit when done.
    /// Memory is allocated for the client instance.
    pub fn init(allocator: Allocator, config: S3Config) !*S3Client {
        const self = try allocator.create(S3Client);

        // Initialize HTTP client
        var client = HttpClient{
            .allocator = allocator,
        };

        // Load system root certificates for HTTPS
        if (!HttpClient.disable_tls) {
            try client.ca_bundle.rescan(allocator);
        }

        errdefer client.deinit();

        self.* = .{
            .allocator = allocator,
            .config = config,
            .http_client = client,
        };

        return self;
    }

    /// Clean up resources used by the client.
    /// This includes the HTTP client and the client instance itself.
    pub fn deinit(self: *S3Client) void {
        self.http_client.deinit();
        self.allocator.destroy(self);
    }

    const RequestOptions = struct {
        body: ?[]const u8 = null,
        content_type: ?[]const u8 = null,
        response: struct {
            head: ?*http.Client.Response.Head = null,
            body: ?*std.io.Writer = null,
        } = .{},
    };

    /// Generic HTTP request handler used by all S3 operations.
    /// Handles request setup, authentication, and execution.
    ///
    /// Parameters:
    ///   - method: HTTP method to use (GET, PUT, DELETE, etc.)
    ///   - uri: Fully qualified URI for the request
    ///   - body: Optional request body data
    ///
    /// Returns: An HTTP request that must be deinit'd by the caller
    pub fn request(
        self: *S3Client,
        method: http.Method,
        uri: Uri,
        opts: RequestOptions,
    ) !http.Client.FetchResult {
        // Create headers map for signing
        var headers = std.StringHashMap([]const u8).init(self.allocator);
        defer headers.deinit();

        // Get the host string from the Component union
        const uri_host = switch (uri.host orelse return S3Error.InvalidResponse) {
            .raw => |h| h,
            .percent_encoded => |h| h,
        };

        // Get path string from Component union and handle root path
        const uri_path = switch (uri.path) {
            .raw => |p| if (p.len == 0) "/" else p,
            .percent_encoded => |p| if (p.len == 0) "/" else p,
        };

        // Add required headers in specific order
        const content_type = opts.content_type orelse "application/xml";
        try headers.put("content-type", content_type);
        try headers.put("host", uri_host);

        // Calculate content hash
        const content_hash = try signer.hashPayload(self.allocator, opts.body orelse "");
        defer self.allocator.free(content_hash);
        try headers.put("x-amz-content-sha256", content_hash);

        // Get current timestamp and format it properly
        const timestamp: i64 = std.time.timestamp();

        // Format current time as x-amz-date header
        const amz_date = try UtcDateTime.init(timestamp).formatAmz(self.allocator);
        defer self.allocator.free(amz_date);
        try headers.put("x-amz-date", amz_date);

        const credentials = signer.Credentials{
            .access_key = self.config.access_key_id,
            .secret_key = self.config.secret_access_key,
            .region = self.config.region,
        };

        const params = signer.SigningParams{
            .method = @tagName(method),
            .path = uri_path,
            .headers = headers,
            .body = opts.body,
            .timestamp = timestamp, // Use same timestamp for signing
        };

        // Generate authorization header
        const auth_header = try signer.signRequest(self.allocator, credentials, params);
        defer self.allocator.free(auth_header);

        // MinIO isn't sending Content-Length for DELETE operations.
        // This results in the fetch hanging until the socket times out (~30s).
        const keep_alive: bool = method.responseHasBody() and method != .DELETE;

        var req = try self.http_client.request(method, uri, .{
            .redirect_behavior = .not_allowed,
            .headers = .{
                .host = .{ .override = uri_host },
                .content_type = .{ .override = content_type },
            },
            .extra_headers = &[_]http.Header{
                .{ .name = "Accept", .value = "application/xml" },
                .{ .name = "x-amz-content-sha256", .value = content_hash },
                .{ .name = "x-amz-date", .value = amz_date },
                .{ .name = "Authorization", .value = auth_header },
            },
            .keep_alive = keep_alive,
        });
        defer req.deinit();

        if (opts.body) |payload| {
            req.transfer_encoding = .{ .content_length = payload.len };
            var b = try req.sendBody(&.{});
            try b.writer.writeAll(payload);
            try b.end();
        } else {
            try req.sendBodiless();
        }

        var response = try req.receiveHead(&.{});

        if (opts.response.head) |response_head| {
            // Dupe underlying head bytes and re-parse
            const head_bytes = try self.allocator.dupe(u8, response.head.bytes);
            response_head.* = try http.Client.Response.Head.parse(head_bytes);
        }

        const response_writer = opts.response.body orelse {
            const reader = response.reader(&.{});
            // TODO: Can remove this check after this is fixed: https://codeberg.org/ziglang/zig/issues/30070
            if (reader != std.Io.Reader.ending) {
                _ = reader.discardRemaining() catch |err| switch (err) {
                    error.ReadFailed => return response.bodyErr().?,
                };
            }
            return .{ .status = response.head.status };
        };

        const decompress_buffer: []u8 = switch (response.head.content_encoding) {
            .identity => &.{},
            .zstd => try self.allocator.alloc(u8, std.compress.zstd.default_window_len),
            .deflate, .gzip => try self.allocator.alloc(u8, std.compress.flate.max_window_len),
            .compress => return error.UnsupportedCompressionMethod,
        };
        defer self.allocator.free(decompress_buffer);

        var transfer_buffer: [64]u8 = undefined;
        var decompress: http.Decompress = undefined;
        const reader = response.readerDecompressing(&transfer_buffer, &decompress, decompress_buffer);

        _ = reader.streamRemaining(response_writer) catch |err| switch (err) {
            error.ReadFailed => return response.bodyErr().?,
            else => |e| return e,
        };

        return .{ .status = response.head.status };
    }
};

test "S3Client request signing" {
    const allocator = std.testing.allocator;

    const config = S3Config{
        .access_key_id = "minioadmin",
        .secret_access_key = "minioadmin",
        .endpoint = "http://localhost:9000",
    };

    var client = try S3Client.init(allocator, config);
    defer client.deinit();

    var head: http.Client.Response.Head = undefined;
    defer allocator.free(head.bytes);

    var response_writer = std.Io.Writer.Allocating.init(allocator);
    defer response_writer.deinit();

    const uri = try Uri.parse("https://examplebucket.s3.amazonaws.com/test.txt");
    _ = try client.request(.GET, uri, .{ .response = .{ .head = &head, .body = &response_writer.writer } });

    var contains_authorization: bool = false;
    var contains_content_sha256: bool = false;
    var contains_date: bool = false;

    var it = head.iterateHeaders();
    while (it.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "authorization")) {
            contains_authorization = true;
        } else if (std.ascii.eqlIgnoreCase(header.name, "x-amz-content-sha256")) {
            contains_content_sha256 = true;
        } else if (std.ascii.eqlIgnoreCase(header.name, "x-amz-date")) {
            contains_date = true;
        }
    }

    // Verify authorization header is present
    try std.testing.expect(contains_authorization);

    // Verify required AWS headers are present
    try std.testing.expect(contains_content_sha256);
    try std.testing.expect(contains_date);
}

test "S3Client initialization" {
    const allocator = std.testing.allocator;

    const config = S3Config{
        .access_key_id = "minioadmin",
        .secret_access_key = "minioadmin",
        .endpoint = "http://localhost:9000",
    };

    var client = try S3Client.init(allocator, config);
    defer client.deinit();

    try std.testing.expectEqualStrings("minioadmin", client.config.access_key_id);
    try std.testing.expectEqualStrings("us-east-1", client.config.region);
    try std.testing.expect(client.config.endpoint == null);
}

test "S3Client custom endpoint" {
    const allocator = std.testing.allocator;

    const config = S3Config{
        .access_key_id = "minioadmin",
        .secret_access_key = "minioadmin",
        .endpoint = "http://localhost:9000",
    };

    var client = try S3Client.init(allocator, config);
    defer client.deinit();

    try std.testing.expectEqualStrings("http://localhost:9000", client.config.endpoint.?);
}

test "S3Client request with body" {
    const allocator = std.testing.allocator;

    const config = S3Config{
        .access_key_id = "minioadmin",
        .secret_access_key = "minioadmin",
        .endpoint = "http://localhost:9000",
    };

    var client = try S3Client.init(allocator, config);
    defer client.deinit();

    const uri = try Uri.parse("https://example.s3.amazonaws.com/test.txt");
    const body = "Hello, S3!";

    var head: http.Client.Response.Head = undefined;
    defer allocator.free(head.bytes);

    _ = try client.request(.PUT, uri, .{ .body = body, .response = .{ .head = &head } });

    var contains_authorization: bool = false;
    var contains_content_sha256: bool = false;
    var contains_date: bool = false;

    var it = head.iterateHeaders();
    while (it.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "authorization")) {
            contains_authorization = true;
        } else if (std.ascii.eqlIgnoreCase(header.name, "x-amz-content-sha256")) {
            contains_content_sha256 = true;
        } else if (std.ascii.eqlIgnoreCase(header.name, "x-amz-date")) {
            contains_date = true;
        }
    }

    try std.testing.expect(contains_authorization);
    try std.testing.expect(contains_content_sha256);
    try std.testing.expect(contains_date);
    try std.testing.expect(head.content_length == body.len);
}

test "S3Client error handling" {
    const allocator = std.testing.allocator;

    const config = S3Config{
        .access_key_id = "minioadmin",
        .secret_access_key = "minioadmin",
        .endpoint = "http://localhost:9000",
    };

    var client = try S3Client.init(allocator, config);
    defer client.deinit();

    const uri = try Uri.parse("https://example.s3.amazonaws.com/test.txt");
    const res = try client.request(.GET, uri, .{});
    _ = res;

    // ???

    // Test error mapping
    // switch (res.status) {
    //     .unauthorized => try std.testing.expectError(S3Error.InvalidCredentials, S3Error.InvalidCredentials),
    //     .forbidden => try std.testing.expectError(S3Error.InvalidCredentials, S3Error.InvalidCredentials),
    //     .not_found => try std.testing.expectError(S3Error.BucketNotFound, S3Error.BucketNotFound),
    //     else => {},
    // }
}
