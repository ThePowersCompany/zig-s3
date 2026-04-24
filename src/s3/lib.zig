//! S3 Client Library for Zig
//!
//! This library provides a simple interface for interacting with Amazon S3 and S3-compatible services.
//! It supports basic operations like creating/deleting buckets and uploading/downloading objects.
//!
//! Basic usage:
//! ```zig
//! const S3Client = @import("s3").S3Client;
//! const S3Config = @import("s3").S3Config;
//!
//! // Initialize client
//! var client = try S3Client.init(allocator, .{
//!     .access_key_id = "your-key",
//!     .secret_access_key = "your-secret",
//! });
//! defer client.deinit();
//!
//! // Use the client
//! try client.createBucket("my-bucket");
//! try client.putObject("my-bucket", "hello.txt", "text/plain", "Hello, S3!");
//! ```
const std = @import("std");
const client = @import("client/implementation.zig");
const bucket_ops = @import("bucket/operations.zig");
const object_ops = @import("object/operations.zig");

pub const PostPolicy = @import("post_policy.zig");
pub const GetPolicy = @import("get_policy.zig");

/// Possible errors that can occur during S3 operations.
/// These errors cover both AWS-specific issues and general HTTP/network problems.
pub const S3Error = error{
    /// Invalid AWS credentials or signature
    InvalidCredentials,
    /// Network or connection failure
    ConnectionFailed,
    /// Requested bucket does not exist
    BucketNotFound,
    /// Requested object does not exist
    ObjectNotFound,
    /// Unexpected response from S3 service
    InvalidResponse,
    /// Error during request signing
    SignatureError,
    /// Memory allocation failure
    OutOfMemory,
    /// Invalid object key
    InvalidObjectKey,
    /// Bucket already exists
    BucketAlreadyExists,
    /// Invalid bucket name
    InvalidBucketName,
    /// Access denied
    AccessDenied,
    /// Service unavailable
    ServiceUnavailable,
};

/// Configuration type for S3 client
pub const S3Config = client.S3Config;

/// Information about a bucket in S3
pub const BucketInfo = bucket_ops.BucketInfo;

/// Information about an object in S3
pub const ObjectInfo = bucket_ops.ObjectInfo;

/// Options for listing objects in a bucket
pub const ListObjectsOptions = bucket_ops.ListObjectsOptions;

/// Metadata about an object in S3
pub const ObjectMetadata = object_ops.ObjectMetadata;

/// Helper struct for uploading different types of content to S3
pub const ObjectUploader = object_ops.ObjectUploader;

/// Main client interface that provides S3 operations.
/// This struct wraps the internal implementation and provides a clean public API.
pub const S3Client = struct {
    /// Internal client implementation
    inner: *client.S3Client,

    /// Initialize a new S3 client with the given configuration.
    /// Memory is allocated for the client and must be freed with deinit.
    ///
    /// Arguments:
    ///     allocator: Memory allocator for the client
    ///     config: S3 configuration including credentials
    ///
    /// Returns: Initialized S3Client
    ///
    /// Errors:
    ///     OutOfMemory: If client allocation fails
    pub fn init(allocator: std.mem.Allocator, config: S3Config) !S3Client {
        return S3Client{
            .inner = try client.S3Client.init(allocator, config),
        };
    }

    /// Clean up resources used by the client.
    /// This must be called when done with the client to avoid memory leaks.
    pub fn deinit(self: *S3Client) void {
        self.inner.deinit();
    }

    /// Create a new bucket.
    /// See bucket/operations.zig for details.
    pub fn createBucket(self: *S3Client, bucket_name: []const u8) !void {
        return bucket_ops.createBucket(self.inner, bucket_name);
    }

    /// Delete an existing bucket.
    /// See bucket/operations.zig for details.
    pub fn deleteBucket(self: *S3Client, bucket_name: []const u8) !void {
        return bucket_ops.deleteBucket(self.inner, bucket_name);
    }

    /// List all buckets owned by the authenticated user.
    /// Memory for the returned slice and its contents must be freed by the caller.
    ///
    /// Returns: Slice of BucketInfo structs
    ///
    /// Errors:
    ///     InvalidCredentials: If authentication fails
    ///     InvalidResponse: If listing fails
    ///     ConnectionFailed: Network or connection issues
    ///     OutOfMemory: Memory allocation failure
    pub fn listBuckets(self: *S3Client) ![]BucketInfo {
        return bucket_ops.listBuckets(self.inner);
    }

    /// List objects in a bucket with optional filtering and pagination.
    /// Memory for the returned slice and its contents must be freed by the caller.
    ///
    /// Arguments:
    ///     bucket_name: Name of the bucket to list
    ///     options: Optional parameters for filtering and pagination
    ///
    /// Returns: Slice of ObjectInfo structs
    ///
    /// Errors:
    ///     BucketNotFound: If the bucket doesn't exist
    ///     InvalidResponse: If listing fails
    ///     ConnectionFailed: Network or connection issues
    ///     OutOfMemory: Memory allocation failure
    pub fn listObjects(self: *S3Client, bucket_name: []const u8, options: ListObjectsOptions) ![]ObjectInfo {
        return bucket_ops.listObjects(self.inner, bucket_name, options);
    }

    /// Upload an object to S3.
    /// See object/operations.zig for details.
    pub fn putObject(self: *S3Client, bucket_name: []const u8, key: []const u8, content_type: []const u8, data: []const u8) !void {
        return object_ops.putObject(self.inner, bucket_name, key, content_type, data);
    }

    /// Retrieves metadata for an object from S3.
    /// See object/operations.zig for details.
    pub fn headObject(self: *S3Client, bucket_name: []const u8, key: []const u8) !ObjectMetadata {
        return object_ops.headObject(self.inner, bucket_name, key);
    }

    /// Download an object from S3.
    /// See object/operations.zig for details.
    pub fn getObject(self: *S3Client, bucket_name: []const u8, key: []const u8) ![]const u8 {
        return object_ops.getObject(self.inner, bucket_name, key);
    }

    /// Delete an object from S3.
    /// See object/operations.zig for details.
    pub fn deleteObject(self: *S3Client, bucket_name: []const u8, key: []const u8) !void {
        return object_ops.deleteObject(self.inner, bucket_name, key);
    }

    /// Create an object uploader helper for this client
    pub fn uploader(self: *S3Client) ObjectUploader {
        return ObjectUploader.init(self.inner);
    }
};

test {
    // Run all tests in the S3 module
    @import("std").testing.refAllDecls(@This());
}
