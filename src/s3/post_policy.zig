const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;

const signer = @import("client/auth/signer.zig");
const UtcDateTime = @import("client/auth/time.zig").UtcDateTime;
const S3Config = @import("client/implementation.zig").S3Config;

const Self = @This();

pub const ConditionMatch = union(enum) {
    /// The form field value must match the value specified.
    exact: []const u8,
    /// The value must start with the specified value.
    @"starts-with": []const u8,
    /// For form fields that accept an upper and lower limit range (in bytes).
    @"content-length-range": struct { min: u64, max: u64 },

    fn jsonWrite(self: *const ConditionMatch, jws: anytype, name: []const u8) !void {
        switch (self.*) {
            .exact => |e| {
                try jws.beginObject();
                try jws.objectField(name);
                try jws.write(e);
                try jws.endObject();
            },
            .@"starts-with" => |sw| {
                try jws.beginArray();
                try jws.write("starts-with");
                try jws.print("\"${s}\"", .{name});
                try jws.write(sw);
                try jws.endArray();
            },
            .@"content-length-range" => |r| {
                try jws.beginArray();
                try jws.write("content-length-range");
                try jws.write(r.min);
                try jws.write(r.max);
                try jws.endArray();
            },
        }
    }
};

pub const ConditionVariable = union(enum) {
    /// Specifies the ACL value that must be used in the form submission.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    acl,
    /// Specifies the acceptable bucket name.
    /// This condition supports `exact` matching condition match type.
    bucket,
    /// The minimum and maximum allowable size for the uploaded content.
    /// This condition supports `content-length-range` condition match type.
    @"content-length-range",
    /// REST-specific headers.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    @"Cache-Control",
    /// REST-specific headers.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    @"Content-Type",
    /// REST-specific headers.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    @"Content-Disposition",
    /// REST-specific headers.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    @"Content-Encoding",
    /// REST-specific headers.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    Expires,
    /// The acceptable key name or a prefix of the uploaded object.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    key,
    /// The URL to which the client is redirected upon successful upload.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    @"success-action-redirect",
    /// The URL to which the client is redirected upon successful upload.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    redirect,

    /// The signing algorithm that must be used during signature calculation. For AWS Signature Version 4, the value is AWS4-HMAC-SHA256.
    /// This condition supports `exact` matching.
    @"x-amz-algorithm",
    /// The credentials that you used to calculate the signature.
    @"x-amz-credential",
    /// The date value specified in the ISO8601 formatted string. For example, 20130728T000000Z.
    /// The date must be same that you used in creating the signing key for signature calculation.
    /// This condition supports `exact` matching.
    @"x-amz-date",
    /// Amazon DevPay security token.
    @"x-amz-security-token",

    /// User-specified metadata.
    /// This condition supports `exact` matching and `starts-with` condition match type.
    meta: []const u8,
    /// The storage class to use for storing the object.
    /// This condition supports `exact` matching.
    @"x-amz-storage-class",
    /// If the bucket is configured as a website, this field redirects requests for this object to another object in the same bucket or to an external URL.
    /// This condition supports `exact` matching.
    @"x-amz-website-redirect-location",
    /// Indicates the algorithm used to create the checksum for the object.
    /// This condition supports `exact` matching.
    @"x-amz-checksum-algorithm": ChecksumAlgorithm,

    fn equals(self: ConditionVariable, other: ConditionVariable) bool {
        return switch (self) {
            .meta => other == .meta and std.mem.eql(u8, self.meta, other.meta),
            else => std.meta.eql(self, other),
        };
    }
};

pub const ChecksumAlgorithm = enum {
    /// Specifies the base64-encoded, 32-bit CRC32 checksum of the object.
    CRC32,
    /// Specifies the base64-encoded, 32-bit CRC32C checksum of the object.
    CRC32C,
    /// Specifies the base64-encoded, 160-bit SHA-1 digest of the object.
    SHA1,
    /// Specifies the base64-encoded, 256-bit SHA-256 digest of the object.
    SHA256,

    fn name(self: ChecksumAlgorithm) []const u8 {
        return switch (self) {
            .CRC32 => "x-amz-checksum-crc32",
            .CRC32C => "x-amz-checksum-crc32c",
            .SHA1 => "x-amz-checksum-sha1",
            .SHA256 => "x-amz-checksum-sha256",
        };
    }
};

pub const Condition = struct {
    variable: ConditionVariable,
    match: ConditionMatch,

    pub fn jsonStringify(self: *const Condition, jws: anytype) !void {
        switch (self.variable) {
            .meta => |meta| try self.match.jsonWrite(jws, meta),
            .@"x-amz-checksum-algorithm" => |algo| {
                const algoMatch: ConditionMatch = .{ .exact = @tagName(algo) };
                try algoMatch.jsonWrite(jws, "x-amz-checksum-algorithm");
                try self.match.jsonWrite(jws, algo.name());
            },
            else => try self.match.jsonWrite(jws, @tagName(self.variable)),
        }
    }

    pub fn formWrite(self: *const Condition, alloc: Allocator, form_data: *FormData) !void {
        const val: []const u8 = switch (self.match) {
            .exact => |e| e,
            .@"starts-with" => |sw| sw,
            else => return,
        };

        switch (self.variable) {
            .meta => |meta| try form_data.put(alloc, meta, val),
            .@"x-amz-checksum-algorithm" => |algo| {
                try form_data.put(alloc, @tagName(self.variable), @tagName(algo));
                try form_data.put(alloc, algo.name(), val);
            },
            else => try form_data.put(alloc, @tagName(self.variable), val),
        }
    }
};

const FormData = std.StringArrayHashMapUnmanaged([]const u8);

_alloc: Allocator,

/// Unix timestamp (in seconds)
expiration: i64,

/// List of conditions in the policy
conditions: std.ArrayList(Condition) = .empty,

/// POST form data
form_data: FormData = .empty,

/// Create a new POST Policy that expires at the Unix timestamp (in seconds).
pub fn expires_at(alloc: Allocator, unix_timestamp_secs: i64) Self {
    return .{
        ._alloc = alloc,
        .expiration = unix_timestamp_secs,
    };
}

/// Create a POST Policy that expires in a certain number of seconds from now.
pub fn expires_in(alloc: Allocator, seconds: u64) Self {
    return .expires_at(alloc, std.time.timestamp() + @as(i64, @intCast(seconds)));
}

pub fn deinit(self: *Self) void {
    self.conditions.deinit(self._alloc);
    self.form_data.deinit(self._alloc);
}

/// Add custom condition to the policy.
pub fn add(self: *Self, cond: Condition) !void {
    try cond.formWrite(self._alloc, &self.form_data);
    try self.conditions.append(self._alloc, cond);
}

/// Determine whether the policy includes the condition variable.
pub fn has(self: *const Self, cv: ConditionVariable) bool {
    for (self.conditions.items) |c| {
        if (c.variable.equals(cv)) {
            return true;
        }
    }
    return false;
}

/// Set bucket name
pub fn setBucket(self: *Self, bucket: []const u8) !void {
    return self.add(.{ .variable = .bucket, .match = .{ .exact = bucket } });
}

/// Set object name
pub fn setKey(self: *Self, key: []const u8) !void {
    return self.add(.{ .variable = .key, .match = .{ .exact = key } });
}

/// Set object name prefix
pub fn setKeyStartsWith(self: *Self, prefix: []const u8) !void {
    return self.add(.{ .variable = .key, .match = .{ .starts_with = prefix } });
}

/// Set content type
pub fn setContentType(self: *Self, key: []const u8) !void {
    return self.add(.{ .variable = .@"Content-Type", .match = .{ .exact = key } });
}

/// Set content type prefix
pub fn setContentTypeStartsWith(self: *Self, prefix: []const u8) !void {
    return self.add(.{ .variable = .@"Content-Type", .match = .{ .starts_with = prefix } });
}

/// Set content disposition
pub fn setContentDisposition(self: *Self, key: []const u8) !void {
    return self.add(.{ .variable = .@"Content-Disposition", .match = .{ .exact = key } });
}

/// Set content length range
pub fn setContentLengthRange(self: *Self, min: u64, max: u64) !void {
    return self.add(.{ .variable = .@"content-length-range", .match = .{ .@"content-length-range" = .{ .min = min, .max = max } } });
}

pub fn jsonStringify(self: *const Self, jws: anytype) !void {
    try jws.beginObject();
    try jws.objectField("expiration");
    try jws.write(UtcDateTime.init(self.expiration));
    try jws.objectField("conditions");
    try jws.write(self.conditions.items);
    try jws.endObject();
}

pub const PresignOptions = struct {
    /// Whether to dupe all of the form data to extend its lifetime.
    dupe: bool = false,
};

pub const Presigned = struct {
    _arena: ArenaAllocator,

    post_url: []const u8,
    form_data: FormData,

    pub fn deinit(self: *Presigned) void {
        self._arena.deinit();
    }
};

/// Presigns the POST Policy
pub fn presign(self: *Self, config: *const S3Config, opts: PresignOptions) !Presigned {
    var arena: ArenaAllocator = .init(self._alloc);
    errdefer arena.deinit();
    const alloc: Allocator = arena.allocator();

    const dt = UtcDateTime.now();
    const date_str = try dt.formatAmzDate(alloc);
    defer alloc.free(date_str);

    if (!self.has(.@"x-amz-date")) {
        try self.add(.{ .variable = .@"x-amz-date", .match = .{ .exact = try dt.formatAmz(alloc) } });
    }
    if (!self.has(.@"x-amz-algorithm")) {
        try self.add(.{ .variable = .@"x-amz-algorithm", .match = .{ .exact = "AWS4-HMAC-SHA256" } });
    }
    if (!self.has(.@"x-amz-credential")) {
        const cred: []const u8 = try std.fmt.allocPrint(
            alloc,
            "{s}/{s}/{s}/s3/aws4_request",
            .{ config.access_key_id, date_str, config.region },
        );
        try self.add(.{ .variable = .@"x-amz-credential", .match = .{ .exact = cred } });
    }

    const policy: []const u8 = base64: {
        const policy_json = try std.json.Stringify.valueAlloc(alloc, self, .{});
        defer alloc.free(policy_json);
        var aw: std.io.Writer.Allocating = .init(alloc);
        defer aw.deinit();
        try std.base64.standard.Encoder.encodeWriter(&aw.writer, policy_json);
        break :base64 try aw.toOwnedSlice();
    };

    // Calculate signature
    const signature: []const u8 = sig: {
        const signing_key = try signer.deriveSigningKey(
            alloc,
            config.secret_access_key,
            date_str,
            config.region,
            "s3",
        );
        defer alloc.free(signing_key);

        break :sig try signer.calculateSignature(alloc, signing_key, policy);
    };

    // Copy the policy's form data
    var form_data: FormData = try .clone(self.form_data, alloc);
    errdefer form_data.deinit(alloc);

    if (opts.dupe) {
        // Clone all of the key-value pairs in the form data
        var it = form_data.iterator();
        while (it.next()) |e| {
            e.key_ptr.* = try alloc.dupe(u8, e.key_ptr.*);
            e.value_ptr.* = try alloc.dupe(u8, e.value_ptr.*);
        }
    }

    // Add final entries into form data
    try form_data.put(alloc, "policy", policy);
    try form_data.put(alloc, "x-amz-signature", signature);

    const bucket_name = form_data.get("bucket") orelse return error.EmptyBucketName;
    const post_url = try config.bucketUri(alloc, bucket_name);

    return .{
        ._arena = arena,
        .post_url = post_url,
        .form_data = form_data,
    };
}
