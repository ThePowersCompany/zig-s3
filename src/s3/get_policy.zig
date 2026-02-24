const std = @import("std");
const eql = std.mem.eql;
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;

const signer = @import("client/auth/signer.zig");
const UtcDateTime = @import("client/auth/time.zig").UtcDateTime;
const S3Config = @import("client/implementation.zig").S3Config;

const expect = std.testing.expect;

const Self = @This();

// DOCS: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html

_alloc: Allocator,

config: *const S3Config,

request: PresignedRequest,

headers: PolicyHeaders,

/// @url (S3 URL)
/// Local minIO: http://localhost:9000
/// Cloudflare r2: https://my-bucket.<ACCOUNT_ID>.r2.cloudflarestorage.com
/// NOTE: Local minIO doesn't use bucket name in the domain
/// instead it's in the path i.e. http://localhost:9000/my-bucket
///
/// @object (Object identifier)
/// If bucket name isn't included in the S3 URL
/// then prepend the bucket name to the object name
/// "my-bucket/57c8951b8111ec9aab959110a46b3fcf7ec8960f8bc0a38163d45b4be2dcd518"
pub const PresignedRequest = struct {
    timestamp: ?i64 = null,
    expires: u32 = 3600,
    url: []const u8,
    object: []const u8,
};

const PolicyHeaders = struct {
    /// Identifies the version of AWS Signature and the algorithm that you used to calculate the signature.
    ///
    /// For AWS Signature Version 4, you set this parameter value to AWS4-HMAC-SHA256.
    /// This string identifies AWS Signature Version 4 (AWS4) and the HMAC-SHA256 algorithm (HMAC-SHA256).
    @"X-Amz-Algorithm": []const u8 = "AWS4-HMAC-SHA256",

    /// In addition to your access key ID, this parameter also provides scope (AWS Region and service) for which the signature is valid.
    /// This value must match the scope you use in signature calculations, discussed in the following section.
    /// The general form for this parameter value is as follows:
    ///
    /// <your-access-key-id>/<date>/<AWS Region>/<AWS-service>/aws4_request
    /// For example:
    ///
    /// AKIAIOSFODNN7EXAMPLE/20130721/us-east-1/s3/aws4_request
    /// For Amazon S3, the AWS-service string is s3.
    /// For a list of S3 AWS-region strings, see Regions and Endpoints in the AWS General Reference.
    @"X-Amz-Credential": []const u8 = "",

    /// The date and time format must follow the ISO 8601 standard, and must be formatted with the "yyyyMMddTHHmmssZ" format.
    /// For example if the date and time was "08/01/2016 15:32:41.982-700" then it must first be converted
    /// to UTC (Coordinated Universal Time) and then submitted as "20160801T223241Z".
    @"X-Amz-Date": []const u8 = "",

    /// Provides the time period, in seconds, for which the generated presigned URL is valid.
    /// For example, 86400 (24 hours). This value is an integer.
    /// The minimum value you can set is 1, and the maximum is 604800 (seven days).
    ///
    /// A presigned URL can be valid for a maximum of seven days because the signing key you use in signature calculation is valid for up to seven days.
    @"X-Amz-Expires": []const u8 = "",

    /// Lists the headers that you used to calculate the signature. The following headers are required in the signature calculations:
    ///
    /// The HTTP 'host' header.
    ///
    /// Any x-amz-* headers that you plan to add to the request.
    ///
    /// Note
    /// For added security, you should sign all the request headers that you plan to include in your request.
    @"X-Amz-SignedHeaders": []const u8 = "host",

    /// Provides the signature to authenticate your request.
    /// This signature must match the signature Amazon S3 calculates; otherwise, Amazon S3 denies the request.
    /// For example, 733255ef022bec3f2a8701cd61d4b371f3f28c9f193a1f02279211d48d5193d7
    @"X-Amz-Signature": []const u8 = "",
};

pub fn init(alloc: Allocator, config: *const S3Config, request: PresignedRequest) Self {
    return .{
        ._alloc = alloc,
        .config = config,
        .request = request,
        .headers = .{},
    };
}

/// Expected format YYYYMMDD
/// Example: 20130524
pub fn getAmzDate(alloc: Allocator, unix_timestamp: i64) ![]const u8 {
    const dt = UtcDateTime.init(unix_timestamp);
    const date_str = try dt.formatAmzDate(alloc);
    return date_str;
}

/// Expected 8601 format: "yyyyMMddTHHmmssZ"
/// Example: 20130524T000000Z
pub fn getAmzDateTime8601(alloc: Allocator, unix_timestamp: i64) ![]const u8 {
    const dt = UtcDateTime.init(unix_timestamp);
    const date_time_str_8601 = try dt.formatAmz(alloc);
    return date_time_str_8601;
}

/// Example: AKIAIOSFODNN7EXAMPLE/0130524/us-east-1/s3/aws4_request
pub fn getAmzCred(alloc: Allocator, access_key: []const u8, date: []const u8, region: []const u8) ![]const u8 {
    const cred: []const u8 = try std.fmt.allocPrint(
        alloc,
        "{s}/{s}/{s}/s3/aws4_request",
        .{ access_key, date, region },
    );
    return cred;
}

/// Expiration time must be between 1 second and 7 days
pub fn getAmzExpires(alloc: Allocator, seconds: u32) ![]const u8 {
    if (!(seconds >= 1 and seconds <= 604800)) return error.ExpiresOutsideBounds;
    const seconds_str = try std.fmt.allocPrint(
        alloc,
        "{d}",
        .{seconds},
    );
    return seconds_str;
}

/// Example: 20130524/us-east-1/s3/aws4_request
pub fn getAmzScope(alloc: Allocator, date: []const u8, region: []const u8) ![]const u8 {
    const scope: []const u8 = try std.fmt.allocPrint(
        alloc,
        "{s}/{s}/s3/aws4_request",
        .{ date, region },
    );
    return scope;
}

// Called from presign(), expects an arena allocator
pub fn createCanonicalRequest(self: *Self, alloc: Allocator, method: []const u8, host: []const u8, object: []const u8) ![]const u8 {
    var canonical: std.ArrayList(u8) = .empty;

    // Add HTTP method (uppercase)
    try canonical.appendSlice(alloc, method);
    try canonical.append(alloc, '\n');

    // Add canonical URI (must be normalized)
    try canonical.append(alloc, '/');
    try canonical.appendSlice(alloc, object);
    try canonical.append(alloc, '\n');

    // NOTE: These are the required headers.
    // If we want to support adding optional headers
    // this should be made dynamic (requires sorting)
    const params = [_][2][]const u8{
        .{ "X-Amz-Algorithm", self.headers.@"X-Amz-Algorithm" },
        .{ "X-Amz-Credential", self.headers.@"X-Amz-Credential" },
        .{ "X-Amz-Date", self.headers.@"X-Amz-Date" },
        .{ "X-Amz-Expires", self.headers.@"X-Amz-Expires" },
        .{ "X-Amz-SignedHeaders", self.headers.@"X-Amz-SignedHeaders" },
    };

    const query_str = try buildPercentEncodedQuery(alloc, &params);

    // Add canonical query string
    try canonical.appendSlice(alloc, query_str);
    try canonical.append(alloc, '\n');

    try canonical.appendSlice(alloc, "host:");
    try canonical.appendSlice(alloc, host);
    try canonical.append(alloc, '\n');
    try canonical.append(alloc, '\n');
    try canonical.appendSlice(alloc, "host");
    try canonical.append(alloc, '\n');
    try canonical.appendSlice(alloc, "UNSIGNED-PAYLOAD");

    std.debug.print("canonical_request:\n\n{s}\n\n", .{canonical.items});
    return try canonical.toOwnedSlice(alloc);
}

// Called from presign(), expects an arena allocator
fn buildPercentEncodedQuery(alloc: Allocator, params: []const [2][]const u8) ![]const u8 {
    var aw: std.io.Writer.Allocating = .init(alloc);
    defer aw.deinit();

    for (params, 0..) |param, i| {
        if (i > 0) try aw.writer.writeByte('&');
        try percentEncode(&aw.writer, param[0]);
        try aw.writer.writeByte('=');
        try percentEncode(&aw.writer, param[1]);
    }

    return aw.toOwnedSlice();
}

pub fn hashCanonicalRequest(alloc: Allocator, canonical_request: []const u8) ![]const u8 {
    const hashed = try signer.hashPayload(alloc, canonical_request);
    std.debug.print("hashed:\n\n{s}\n\n", .{hashed});
    return hashed;
}

fn createStringToSign(alloc: Allocator, timestamp_8601: []const u8, scope: []const u8, canonical_request_hash: []const u8) ![]const u8 {
    var string_to_sign: std.ArrayList(u8) = .empty;

    try string_to_sign.appendSlice(alloc, "AWS4-HMAC-SHA256");
    try string_to_sign.append(alloc, '\n');
    try string_to_sign.appendSlice(alloc, timestamp_8601);
    try string_to_sign.append(alloc, '\n');
    try string_to_sign.appendSlice(alloc, scope);
    try string_to_sign.append(alloc, '\n');
    try string_to_sign.appendSlice(alloc, canonical_request_hash);

    std.debug.print("string to sign:\n\n{s}\n\n", .{string_to_sign.items});
    return try string_to_sign.toOwnedSlice(alloc);
}

/// Valid characters in a query string value '/' is encoded as %2F.
fn isValidQueryChar(c: u8) bool {
    return switch (c) {
        'A'...'Z',
        'a'...'z',
        '0'...'9',
        '-',
        '_',
        '.',
        '~',
        => true,
        else => false,
    };
}

fn percentEncode(writer: *std.Io.Writer, value: []const u8) !void {
    try std.Uri.Component.percentEncode(writer, value, isValidQueryChar);
}

// Called from presign(), expects an arena allocator
fn buildQuery(self: *Self, alloc: Allocator) ![]const u8 {
    var query: std.ArrayList(u8) = .empty;

    try query.append(alloc, '?');

    // NOTE: These are the required headers.
    // If we want to support adding optional headers (in X-Amz-SignedHeaders)
    // this should be made dynamic (requires sorting)
    const params = [_][2][]const u8{
        .{ "X-Amz-Algorithm", self.headers.@"X-Amz-Algorithm" },
        .{ "X-Amz-Credential", self.headers.@"X-Amz-Credential" },
        .{ "X-Amz-Date", self.headers.@"X-Amz-Date" },
        .{ "X-Amz-Expires", self.headers.@"X-Amz-Expires" },
        .{ "X-Amz-SignedHeaders", self.headers.@"X-Amz-SignedHeaders" },
        .{ "X-Amz-Signature", self.headers.@"X-Amz-Signature" },
    };

    const query_str = try buildPercentEncodedQuery(alloc, &params);

    try query.appendSlice(alloc, query_str);
    std.debug.print("query:\n\n{s}\n\n", .{query.items});
    return try query.toOwnedSlice(alloc);
}

/// Presigns the GET Policy
pub fn presign(self: *Self) ![]const u8 {
    var arena: ArenaAllocator = .init(self._alloc);
    defer arena.deinit();
    const alloc: Allocator = arena.allocator();

    const config = self.config;
    const request = self.request;

    const timestamp = request.timestamp orelse std.time.timestamp();
    const date_str = try getAmzDate(alloc, timestamp);

    const cred = try getAmzCred(alloc, config.access_key_id, date_str, config.region);

    const date_time_8601 = try getAmzDateTime8601(alloc, timestamp);

    const expires = try getAmzExpires(alloc, request.expires);

    self.headers = .{
        .@"X-Amz-Credential" = cred,
        .@"X-Amz-Date" = date_time_8601,
        .@"X-Amz-Expires" = expires,
    };

    const uri = try std.Uri.parse(request.url);
    const host = try std.fmt.allocPrint(alloc, "{f}", .{uri.fmt(.{
        .authentication = true,
        .authority = true,
        .fragment = true,
        .port = true,
    })});
    const obj = request.object;

    std.debug.print("debug host:\n\n{s}\n\n", .{host});

    const canonical_request = try self.createCanonicalRequest(alloc, "GET", host, obj);

    const hashed_canonical_request = try hashCanonicalRequest(alloc, canonical_request);

    const scope = try getAmzScope(alloc, date_str, config.region);

    const string_to_sign = try createStringToSign(alloc, date_time_8601, scope, hashed_canonical_request);

    // Calculate signature
    const signature: []const u8 = sig: {
        const signing_key = try signer.deriveSigningKey(
            alloc,
            config.secret_access_key,
            date_str,
            config.region,
            "s3",
        );

        break :sig try signer.calculateSignature(alloc, signing_key, string_to_sign);
    };
    self.headers.@"X-Amz-Signature" = signature;

    const query = try self.buildQuery(alloc);

    var get_url: std.ArrayList(u8) = .empty;

    try get_url.appendSlice(alloc, request.url);
    if (request.url[request.url.len - 1] != '/') {
        try get_url.appendSlice(alloc, "/");
    }

    try get_url.appendSlice(alloc, obj);
    try get_url.appendSlice(alloc, query);

    std.debug.print("get_url:\n\n{s}\n\n", .{get_url.items});

    return try self._alloc.dupe(u8, get_url.items);
}

// Note: run `zig test src/s3/get_policy.zig --test-filter "get_policy"`
//       to only run tests in this file
const TestPolicy = struct {
    policy: Self,
    date: []const u8,
    date_time_8601: []const u8,
    region: []const u8,
    cred: []const u8,
    expires: []const u8,

    pub fn deinit(self: *TestPolicy, alloc: Allocator) void {
        alloc.free(self.date);
        alloc.free(self.date_time_8601);
        alloc.free(self.cred);
        alloc.free(self.expires);
    }
};

fn buildTestPolicy(alloc: Allocator, timestamp: i64, expires_seconds: u32) !TestPolicy {
    const date = try getAmzDate(alloc, timestamp);
    errdefer alloc.free(date);

    const date_time_8601 = try getAmzDateTime8601(alloc, timestamp);
    errdefer alloc.free(date_time_8601);

    const cred = try getAmzCred(alloc, "AKIAIOSFODNN7EXAMPLE", date, "us-east-1");
    errdefer alloc.free(cred);

    const expires = try getAmzExpires(alloc, expires_seconds);
    errdefer alloc.free(expires);

    const headers: PolicyHeaders = .{
        .@"X-Amz-Credential" = cred,
        .@"X-Amz-Date" = date_time_8601,
        .@"X-Amz-Expires" = expires,
    };

    const config: S3Config = .{
        .access_key_id = "AKIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        .endpoint = "https://examplebucket.s3.amazonaws.com",
    };

    const request = PresignedRequest{
        .timestamp = timestamp,
        .expires = expires_seconds,
        .url = "https://examplebucket.s3.amazonaws.com",
        .object = "test.txt",
    };

    return .{
        .date = date,
        .date_time_8601 = date_time_8601,
        .region = "us-east-1",
        .cred = cred,
        .expires = expires,
        .policy = .{
            ._alloc = alloc,
            .config = &config,
            .request = request,
            .headers = headers,
        },
    };
}

test "test X-Amz-Algorithm" {
    const alloc = std.testing.allocator;

    var tp = try buildTestPolicy(alloc, 1369353600, 86400);
    defer tp.deinit(alloc);

    try expect(eql(u8, tp.policy.headers.@"X-Amz-Algorithm", "AWS4-HMAC-SHA256"));
}

test "test getAmzDate" {
    const alloc = std.testing.allocator;
    const date = try getAmzDate(alloc, 1771693969);
    defer alloc.free(date);

    try expect(eql(u8, date, "20260221"));
}

test "test getAmzDateTime8601" {
    const alloc = std.testing.allocator;
    const date_time_8601 = try getAmzDateTime8601(alloc, 1771693969);
    defer alloc.free(date_time_8601);
    // Expected 8601 format: "yyyyMMddTHHmmssZ"
    try expect(eql(u8, date_time_8601, "20260221T171249Z"));
}

test "test getAmzCred" {
    const alloc = std.testing.allocator;
    const access_key = "AKIAIOSFODNN7EXAMPLE";

    const date = try getAmzDate(alloc, 1771693969);
    defer alloc.free(date);

    const region = "us-east-1";

    const cred = try getAmzCred(alloc, access_key, date, region);
    defer alloc.free(cred);

    try expect(eql(u8, cred, "AKIAIOSFODNN7EXAMPLE/20260221/us-east-1/s3/aws4_request"));
}

test "test getAmzScope" {
    const alloc = std.testing.allocator;

    const date = try getAmzDate(alloc, 1771693969);
    defer alloc.free(date);

    const region = "us-east-1";

    const cred = try getAmzScope(alloc, date, region);
    defer alloc.free(cred);

    try expect(eql(u8, cred, "20260221/us-east-1/s3/aws4_request"));
}

test "test getAmzExpires" {
    const alloc = std.testing.allocator;
    const expires = try getAmzExpires(alloc, 1000);
    defer alloc.free(expires);
    try expect(std.mem.eql(u8, expires, "1000"));

    _ = getAmzExpires(alloc, 0) catch |err| {
        try expect(err == error.ExpiresOutsideBounds);
    };

    _ = getAmzExpires(alloc, 1_000_000) catch |err| {
        try expect(err == error.ExpiresOutsideBounds);
    };
}

test "createCanonicalRequest" {
    var arena: ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const alloc: Allocator = arena.allocator();

    var tp = try buildTestPolicy(alloc, 1369353600, 86400);

    const host = "examplebucket.s3.amazonaws.com";

    const canonical_request = try tp.policy.createCanonicalRequest(alloc, "GET", host, "test.txt");

    const canonical_request_test =
        \\GET
        \\/test.txt
        \\X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host
        \\host:examplebucket.s3.amazonaws.com
        \\
        \\host
        \\UNSIGNED-PAYLOAD
    ;

    try std.testing.expect(canonical_request.len == canonical_request_test.len);
    try std.testing.expectEqualStrings(canonical_request, canonical_request_test);
}

test "hash canonical request" {
    var arena: ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const alloc: Allocator = arena.allocator();

    var tp = try buildTestPolicy(alloc, 1369353600, 86400);

    const host = "examplebucket.s3.amazonaws.com";

    const canonical_request = try tp.policy.createCanonicalRequest(alloc, "GET", host, "test.txt");

    const canonical_request_test =
        \\GET
        \\/test.txt
        \\X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host
        \\host:examplebucket.s3.amazonaws.com
        \\
        \\host
        \\UNSIGNED-PAYLOAD
    ;

    try std.testing.expect(canonical_request.len == canonical_request_test.len);
    try std.testing.expectEqualStrings(canonical_request, canonical_request_test);

    const hashed_canonical_request = try hashCanonicalRequest(alloc, canonical_request);

    const expected_hash = "3bfa292879f6447bbcda7001decf97f4a54dc650c8942174ae0a9121cf58ad04";

    try std.testing.expectEqualStrings(expected_hash, hashed_canonical_request);
}

test "string to sign" {
    var arena: ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const alloc: Allocator = arena.allocator();

    var tp = try buildTestPolicy(alloc, 1369353600, 86400);

    const host = "examplebucket.s3.amazonaws.com";

    const canonical_request = try tp.policy.createCanonicalRequest(alloc, "GET", host, "test.txt");

    const canonical_request_test =
        \\GET
        \\/test.txt
        \\X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host
        \\host:examplebucket.s3.amazonaws.com
        \\
        \\host
        \\UNSIGNED-PAYLOAD
    ;

    try std.testing.expect(canonical_request.len == canonical_request_test.len);
    try std.testing.expectEqualStrings(canonical_request, canonical_request_test);

    const hashed_canonical_request = try hashCanonicalRequest(alloc, canonical_request);

    const expected_hash = "3bfa292879f6447bbcda7001decf97f4a54dc650c8942174ae0a9121cf58ad04";

    try std.testing.expectEqualStrings(expected_hash, hashed_canonical_request);

    const scope = try getAmzScope(alloc, tp.date, tp.region);

    const string_to_sign = try createStringToSign(alloc, tp.date_time_8601, scope, hashed_canonical_request);

    const expected_string_to_sign =
        \\AWS4-HMAC-SHA256
        \\20130524T000000Z
        \\20130524/us-east-1/s3/aws4_request
        \\3bfa292879f6447bbcda7001decf97f4a54dc650c8942174ae0a9121cf58ad04
    ;

    try std.testing.expectEqualStrings(expected_string_to_sign, string_to_sign);
}

test "signature" {
    var arena: ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const alloc: Allocator = arena.allocator();

    var tp = try buildTestPolicy(alloc, 1369353600, 86400);
    defer tp.deinit(alloc);

    const host = "examplebucket.s3.amazonaws.com";
    const canonical_request = try tp.policy.createCanonicalRequest(alloc, "GET", host, "test.txt");

    const canonical_request_test =
        \\GET
        \\/test.txt
        \\X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host
        \\host:examplebucket.s3.amazonaws.com
        \\
        \\host
        \\UNSIGNED-PAYLOAD
    ;

    try std.testing.expect(canonical_request.len == canonical_request_test.len);
    try std.testing.expectEqualStrings(canonical_request, canonical_request_test);

    const hashed_canonical_request = try hashCanonicalRequest(alloc, canonical_request);

    const expected_hash = "3bfa292879f6447bbcda7001decf97f4a54dc650c8942174ae0a9121cf58ad04";

    try std.testing.expectEqualStrings(expected_hash, hashed_canonical_request);

    const scope = try getAmzScope(alloc, tp.date, tp.region);

    const string_to_sign = try createStringToSign(alloc, tp.date_time_8601, scope, hashed_canonical_request);

    const expected_string_to_sign =
        \\AWS4-HMAC-SHA256
        \\20130524T000000Z
        \\20130524/us-east-1/s3/aws4_request
        \\3bfa292879f6447bbcda7001decf97f4a54dc650c8942174ae0a9121cf58ad04
    ;

    try std.testing.expectEqualStrings(expected_string_to_sign, string_to_sign);
    const secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    // Calculate signature
    const signature: []const u8 = sig: {
        const signing_key = try signer.deriveSigningKey(
            alloc,
            secret_access_key,
            tp.date,
            tp.region,
            "s3",
        );

        break :sig try signer.calculateSignature(alloc, signing_key, string_to_sign);
    };

    const expected_signature = "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404";

    try std.testing.expectEqualStrings(expected_signature, signature);
}

test "buildQuery" {
    var arena: ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const alloc: Allocator = arena.allocator();

    var tp = try buildTestPolicy(alloc, 1369353600, 86400);
    const host = "examplebucket.s3.amazonaws.com";

    const canonical_request = try tp.policy.createCanonicalRequest(alloc, "GET", host, "test.txt");

    const canonical_request_test =
        \\GET
        \\/test.txt
        \\X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host
        \\host:examplebucket.s3.amazonaws.com
        \\
        \\host
        \\UNSIGNED-PAYLOAD
    ;

    try std.testing.expect(canonical_request.len == canonical_request_test.len);
    try std.testing.expectEqualStrings(canonical_request, canonical_request_test);

    const hashed_canonical_request = try hashCanonicalRequest(alloc, canonical_request);

    const expected_hash = "3bfa292879f6447bbcda7001decf97f4a54dc650c8942174ae0a9121cf58ad04";

    try std.testing.expectEqualStrings(expected_hash, hashed_canonical_request);

    const scope = try getAmzScope(alloc, tp.date, tp.region);

    const string_to_sign = try createStringToSign(alloc, tp.date_time_8601, scope, hashed_canonical_request);

    const expected_string_to_sign =
        \\AWS4-HMAC-SHA256
        \\20130524T000000Z
        \\20130524/us-east-1/s3/aws4_request
        \\3bfa292879f6447bbcda7001decf97f4a54dc650c8942174ae0a9121cf58ad04
    ;

    try std.testing.expectEqualStrings(expected_string_to_sign, string_to_sign);
    const secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    // Calculate signature
    const signature: []const u8 = sig: {
        const signing_key = try signer.deriveSigningKey(
            alloc,
            secret_access_key,
            tp.date,
            tp.region,
            "s3",
        );

        break :sig try signer.calculateSignature(alloc, signing_key, string_to_sign);
    };

    const expected_signature = "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404";

    try std.testing.expectEqualStrings(expected_signature, signature);

    tp.policy.headers.@"X-Amz-Signature" = signature;

    const query = try tp.policy.buildQuery(alloc);

    const expected_query = "?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404";

    try std.testing.expectEqualStrings(expected_query, query);
}

test "get_policy presign" {
    const alloc = std.testing.allocator;

    var tp = try buildTestPolicy(alloc, 1369353600, 86400);
    defer tp.deinit(alloc);

    const presigned_get_url = try tp.policy.presign();
    defer alloc.free(presigned_get_url);

    const expected_presigned_get_url = "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404";

    try std.testing.expectEqualStrings(expected_presigned_get_url, presigned_get_url);
}
