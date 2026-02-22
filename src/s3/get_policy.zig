const std = @import("std");
const eql = std.mem.eql;
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;

const signer = @import("client/auth/signer.zig");
const UtcDateTime = @import("client/auth/time.zig").UtcDateTime;
const S3Config = @import("client/implementation.zig").S3Config;
const percentEncode = std.Uri.Component.percentEncode;

const expect = std.testing.expect;

const Self = @This();

//_alloc: Allocator,

/// Unix timestamp (in seconds)
// expiration: i64,

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

pub fn getAmzDate(alloc: Allocator, unix_timestamp: i64) ![]const u8 {
    const dt = UtcDateTime.init(unix_timestamp);
    const date_str = try dt.formatAmzDate(alloc);
    return date_str;
}

pub fn getAmzDate8601(alloc: Allocator, unix_timestamp: i64) ![]const u8 {
    const dt = UtcDateTime.init(unix_timestamp);
    const date_str_8601 = try dt.formatAmz(alloc);
    return date_str_8601;
}

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

pub fn createCanonicalRequest(self: Self, alloc: Allocator, method: []const u8, object: []const u8) ![]const u8 {
    var canonical: std.ArrayList(u8) = .empty;
    errdefer canonical.deinit(alloc);

    // Add HTTP method (uppercase)
    try canonical.appendSlice(alloc, method);
    try canonical.append(alloc, '\n');

    // Add canonical URI (must be normalized)
    try canonical.append(alloc, '/');
    try canonical.appendSlice(alloc, object);
    try canonical.append(alloc, '\n');

    var params = std.StringHashMap([]const u8).init(alloc);
    defer params.deinit();

    try params.put("X-Amz-Algorithm", self.@"X-Amz-Algorithm");
    try params.put("X-Amz-Credential", self.@"X-Amz-Credential");
    try params.put("X-Amz-Date", self.@"X-Amz-Date");
    try params.put("X-Amz-Expires", self.@"X-Amz-Expires");
    try params.put("X-Amz-SignedHeaders", self.@"X-Amz-SignedHeaders");

    // Create sorted list of header names for consistent ordering
    var canonical_query: std.ArrayList([]const u8) = .empty;
    defer canonical_query.deinit(alloc);
    var params_it = params.iterator();
    while (params_it.next()) |entry| {
        const param = try std.fmt.allocPrint(alloc, "{s}={s}&", .{ entry.key_ptr.*, entry.value_ptr.* });
        errdefer alloc.free(param);

        try canonical_query.append(alloc, param);
        //     if (params_it.index != 4) {
        //         try canonical_query.append(alloc, "&");
        //     }
    }
    defer {
        for (canonical_query.items) |name| {
            alloc.free(name);
        }
    }

    // Sort header names alphabetically
    std.mem.sortUnstable([]const u8, canonical_query.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);

    const query_str = try std.mem.join(alloc, "", canonical_query.items);
    defer alloc.free(query_str);

    var aw: std.io.Writer.Allocating = .init(alloc);
    defer aw.deinit();

    try percentEncodeQuery(&aw.writer, query_str);

    const encoded = try aw.toOwnedSlice();
    defer alloc.free(encoded);

    const query = try std.fmt.allocPrint(
        alloc,
        "{s}",
        .{encoded[0 .. encoded.len - 1]},
    );
    defer alloc.free(query);

    // Add canonical query string
    try canonical.appendSlice(alloc, query);
    try canonical.append(alloc, '\n');

    try canonical.appendSlice(alloc, "host:examplebucket.s3.amazonaws.com");
    try canonical.append(alloc, '\n');
    try canonical.append(alloc, '\n');
    try canonical.appendSlice(alloc, "host");
    try canonical.append(alloc, '\n');
    try canonical.appendSlice(alloc, "UNSIGNED-PAYLOAD");

    std.debug.print("canonical_request:\n\n{s}\n\n", .{canonical.items});
    return canonical.toOwnedSlice(alloc);
}

/// Valid characters in a query string value — '/' is encoded as %2F.
fn isValidQueryChar(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '_', '.', '~', '&', '=' => true,
        else => false,
    };
}
fn percentEncodeQuery(writer: *std.Io.Writer, value: []const u8) !void {
    try std.Uri.Component.percentEncode(writer, value, isValidQueryChar);
}

// pub fn calcSignature(alloc: Allocator, secret_access_key: []const u8, date_str: []const u8, region: []const u8) ![]const u8 {
//     // Calculate signature
//     const signature: []const u8 = sig: {
//         const signing_key = try signer.deriveSigningKey(
//             alloc,
//             secret_access_key,
//             date_str,
//             region,
//             "s3",
//         );
//         defer alloc.free(signing_key);
//
//         break :sig try signer.calculateSignature(alloc, signing_key, policy);
//     };
// }

// pub const Presigned = struct {
//     _arena: ArenaAllocator,
//
//     get_url: []const u8,
//
//     pub fn deinit(self: *Presigned) void {
//         self._arena.deinit();
//     }
// };

// /// Presigns the GET Policy
// pub fn presign(self: *Self, config: *const S3Config) !Presigned {
//     var arena: ArenaAllocator = .init(self._alloc);
//     errdefer arena.deinit();
//     const alloc: Allocator = arena.allocator();
//
//     const dt = UtcDateTime.now();
//     const date_str = try dt.formatAmzDate(alloc);
//     defer alloc.free(date_str);
//
//     if (!self.has(.@"x-amz-date")) {
//         try self.add(.{ .variable = .@"x-amz-date", .match = .{ .exact = try dt.formatAmz(alloc) } });
//     }
//     if (!self.has(.@"x-amz-algorithm")) {
//         try self.add(.{ .variable = .@"x-amz-algorithm", .match = .{ .exact = "AWS4-HMAC-SHA256" } });
//     }
//     if (!self.has(.@"x-amz-credential")) {
//         const cred: []const u8 = try std.fmt.allocPrint(
//             alloc,
//             "{s}/{s}/{s}/s3/aws4_request",
//             .{ config.access_key_id, date_str, config.region },
//         );
//         try self.add(.{ .variable = .@"x-amz-credential", .match = .{ .exact = cred } });
//     }
//
//     const policy: []const u8 = base64: {
//         const policy_json = try std.json.Stringify.valueAlloc(alloc, self, .{});
//         defer alloc.free(policy_json);
//         var aw: std.io.Writer.Allocating = .init(alloc);
//         defer aw.deinit();
//         try std.base64.standard.Encoder.encodeWriter(&aw.writer, policy_json);
//         break :base64 try aw.toOwnedSlice();
//     };
//
//     // Calculate signature
//     const signature: []const u8 = sig: {
//         const signing_key = try signer.deriveSigningKey(
//             alloc,
//             config.secret_access_key,
//             date_str,
//             config.region,
//             "s3",
//         );
//         defer alloc.free(signing_key);
//
//         break :sig try signer.calculateSignature(alloc, signing_key, policy);
//     };
//
//     // Copy the policy's form data
//     var form_data: FormData = try .clone(self.form_data, alloc);
//     errdefer form_data.deinit(alloc);
//
//     if (opts.dupe) {
//         // Clone all of the key-value pairs in the form data
//         var it = form_data.iterator();
//         while (it.next()) |e| {
//             e.key_ptr.* = try alloc.dupe(u8, e.key_ptr.*);
//             e.value_ptr.* = try alloc.dupe(u8, e.value_ptr.*);
//         }
//     }
//
//     // Add final entries into form data
//     try form_data.put(alloc, "policy", policy);
//     try form_data.put(alloc, "x-amz-signature", signature);
//
//     const endpoint = if (config.endpoint) |ep| ep else try std.fmt.allocPrint(alloc, "https://s3.{s}.amazonaws.com", .{config.region});
//     defer if (config.endpoint == null) alloc.free(endpoint);
//     if (endpoint.len == 0) {
//         return error.EmptyEndpoint;
//     }
//
//     var post_url_writer: std.io.Writer.Allocating = .init(alloc);
//     defer post_url_writer.deinit();
//     try post_url_writer.writer.writeAll(endpoint);
//     if (form_data.get("bucket")) |bucket_name| {
//         if (endpoint[endpoint.len - 1] != '/') {
//             _ = try post_url_writer.writer.write("/");
//         }
//         _ = try post_url_writer.writer.write(bucket_name);
//     }
//     const post_url: []const u8 = try post_url_writer.toOwnedSlice();
//
//     return .{
//         ._arena = arena,
//         .post_url = post_url,
//         .form_data = form_data,
//     };
// }

test "test X-Amz-Algorithm" {
    const get_policy = Self{};

    try expect(eql(u8, get_policy.@"X-Amz-Algorithm", "AWS4-HMAC-SHA256"));
}

test "test getAmzDate" {
    const alloc = std.testing.allocator;
    const date = try getAmzDate(alloc, 1771693969);
    defer alloc.free(date);

    try expect(eql(u8, date, "20260221"));
}

test "test getAmzDate8601" {
    const alloc = std.testing.allocator;
    const date_8601 = try getAmzDate8601(alloc, 1771693969);
    defer alloc.free(date_8601);
    // Expected 8601 format: "yyyyMMddTHHmmssZ"
    try expect(eql(u8, date_8601, "20260221T171249Z"));
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

test "test getAmzExpires" {
    const alloc = std.testing.allocator;
    {
        const expires = try getAmzExpires(alloc, 1000);
        defer alloc.free(expires);
        try expect(std.mem.eql(u8, expires, "1000"));
    }
    {
        _ = getAmzExpires(alloc, 0) catch |err| {
            try expect(err == error.ExpiresOutsideBounds);
        };
    }
    {
        _ = getAmzExpires(alloc, 1_000_000) catch |err| {
            try expect(err == error.ExpiresOutsideBounds);
        };
    }
}

test "createCanonicalRequest" {
    var get_policy = Self{};
    const alloc = std.testing.allocator;

    var headers = std.StringHashMap([]const u8).init(alloc);
    defer headers.deinit();

    try headers.put("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
    try headers.put("X-Amz-Credential", "AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request");
    try headers.put("X-Amz-Date", "20130524T000000Z");
    try headers.put("host", "examplebucket.s3.amazonaws.com");
    try headers.put("X-Amz-Expires", "86400");
    try headers.put("X-Amz-SignedHeaders", "host");
    try headers.put("X-Amz-Signature", "UNSIGNED-PAYLOAD");

    const access_key = "AKIAIOSFODNN7EXAMPLE";

    const date = try getAmzDate(alloc, 1369353600);
    defer alloc.free(date);

    const region = "us-east-1";

    const cred = try getAmzCred(alloc, access_key, date, region);
    get_policy.@"X-Amz-Credential" = cred;
    defer alloc.free(cred);

    const date_8601 = try getAmzDate8601(alloc, 1369353600);
    get_policy.@"X-Amz-Date" = date_8601;
    defer alloc.free(date_8601);

    const expires = try getAmzExpires(alloc, 86400);
    defer alloc.free(expires);
    get_policy.@"X-Amz-Expires" = expires;

    const canonical_request = try get_policy.createCanonicalRequest(alloc, "GET", "test.txt");
    defer alloc.free(canonical_request);

    const canonical_request_test =
        \\GET
        \\/test.txt
        \\X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host
        \\host:examplebucket.s3.amazonaws.com
        \\
        \\host
        \\UNSIGNED-PAYLOAD
    ;

    try std.testing.expect(canonical_request.len == canonical_request.len);
    try std.testing.expectStringStartsWith(canonical_request, canonical_request_test);
}

// test "creates presigned get url" {
//     // DOCS: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
//     const bucket = "https://examplebucket.s3.amazonaws.com";
//     const object = "test.txt";
//     const request_timestamp = "20130524T000000Z";
//     const region = "us-east-1";
//     const aws_access_key_id = "AKIAIOSFODNN7EXAMPLE";
//     const aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
//
//     const presigned_get_url =
//         \\ https://examplebucket.s3.amazonaws.com/test.txt
//         \\ ?X-Amz-Algorithm=AWS4-HMAC-SHA256
//         \\ &X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request
//         \\ &X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host
//         \\ &X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404
//     ;
// }
