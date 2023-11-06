const std = @import("std");

const c = @cImport({
    @cInclude("zig_ssl_config.h");
    @cInclude("mbedtls/entropy.h");
    @cInclude("mbedtls/ctr_drbg.h");
    @cInclude("mbedtls/x509.h");
    @cInclude("mbedtls/ssl.h");
    @cInclude("mbedtls/net_sockets.h");
    @cInclude("mbedtls/error.h");
    @cInclude("mbedtls/debug.h");
    @cInclude("mbedtls/ssl_cache.h");
});

pub const mbedTLS = struct {
    listen_fd: *c.mbedtls_net_context,
    client_fd: *c.mbedtls_net_context,

    entropy: *c.mbedtls_entropy_context,
    ctr_drbg: *c.mbedtls_ctr_drbg_context,
    ssl: *c.mbedtls_ssl_context,

    conf: *c.mbedtls_ssl_config,

    srvcrt: *c.mbedtls_x509_crt,
    pkey: *c.mbedtls_pk_context,
    cache: *c.mbedtls_ssl_cache_context,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !mbedTLS {
        var listen_fd_ctx = try allocator.create(c.mbedtls_net_context);
        var client_fd_ctx = try allocator.create(c.mbedtls_net_context);

        var entropy_ctx = try allocator.create(c.mbedtls_entropy_context);
        var ctr_drbg_ctx = try allocator.create(c.mbedtls_ctr_drbg_context);
        var ssl_ctx = try allocator.create(c.mbedtls_ssl_context);

        var conf_ctx = c.zmbedtls_ssl_config_alloc();

        var srvcrt_ctx = try allocator.create(c.mbedtls_x509_crt);
        var pkey_ctx = try allocator.create(c.mbedtls_pk_context);
        var cache_ctx = try allocator.create(c.mbedtls_ssl_cache_context);

        c.mbedtls_net_init(listen_fd_ctx);
        c.mbedtls_net_init(client_fd_ctx);

        c.mbedtls_entropy_init(entropy_ctx);
        c.mbedtls_ctr_drbg_init(ctr_drbg_ctx);
        c.mbedtls_ssl_init(ssl_ctx);

        c.zmbedtls_ssl_config_init(conf_ctx);

        c.mbedtls_x509_crt_init(srvcrt_ctx);
        c.mbedtls_pk_init(pkey_ctx);
        c.mbedtls_ssl_cache_init(cache_ctx);

        return mbedTLS{
            .listen_fd = listen_fd_ctx,
            .client_fd = client_fd_ctx,
            .entropy = entropy_ctx,
            .ctr_drbg = ctr_drbg_ctx,
            .ssl = ssl_ctx,
            .conf = @ptrCast(conf_ctx),
            .srvcrt = srvcrt_ctx,
            .pkey = pkey_ctx,
            .cache = cache_ctx,
            .allocator = allocator,
        };
    }

    pub fn seed(self: *mbedTLS) !void {
        var ret: i32 = undefined;
        const pers = "SSL";
        ret = c.mbedtls_ctr_drbg_seed(self.ctr_drbg, c.mbedtls_entropy_func, self.entropy, pers, pers.len);

        if (ret != 0) {
            std.debug.print("Seed Failed: {}\n", .{ret});
            return error.SeedFailed;
        }
    }

    pub fn set_certificate(self: mbedTLS, certificate_path: [*c]const u8) !void {
        var ret: i32 = undefined;
        ret = c.mbedtls_x509_crt_parse_file(self.srvcrt, certificate_path);

        if (ret != 0) {
            std.debug.print("Parsing Certificate Failed: {}\n", .{ret});
            return error.ParseCertificateFailed;
        }
    }

    pub fn set_key(self: mbedTLS, key_path: [*c]const u8) !void {
        var ret: i32 = undefined;
        ret = c.mbedtls_pk_parse_keyfile(self.pkey, key_path, 0);

        if (ret != 0) {
            std.debug.print("Parsing Key Failed: {}\n", .{ret});
            return error.ParseKeyFailed;
        }
    }

    pub fn create_socket(self:mbedTLS) !void {
        var ret: i32 = undefined;
        ret = c.mbedtls_net_bind(self.listen_fd, null, "4433", c.MBEDTLS_NET_PROTO_TCP);

        if (ret != 0) {
            std.debug.print("Bind Failed: {}\n", .{ret});
            return error.BindFailed;
        }

        ret = c.mbedtls_ssl_config_defaults(self.conf, c.MBEDTLS_SSL_IS_SERVER, c.MBEDTLS_SSL_TRANSPORT_STREAM, c.MBEDTLS_SSL_PRESET_DEFAULT);

        if (ret != 0) {
            std.debug.print("SSL Defaults failed: {}\n", .{ret});
            return error.SSLDefaultsFailed;
        }

        c.mbedtls_ssl_conf_rng(self.conf, c.mbedtls_ctr_drbg_random, self.ctr_drbg);
        c.mbedtls_ssl_conf_session_cache(self.conf, self.cache, c.mbedtls_ssl_cache_get, c.mbedtls_ssl_cache_set);
        c.mbedtls_ssl_conf_ca_chain(self.conf, self.srvcrt.next, null);

        ret = c.mbedtls_ssl_conf_own_cert(self.conf, self.srvcrt, self.pkey);
        if (ret != 0) {
            std.debug.print("SSL Conf Own Cert Returned: {}\n", .{ret});
            return error.SSLOwnCert;
        }

        ret = c.mbedtls_ssl_setup(self.ssl, self.conf);
        if (ret != 0) {
            std.debug.print("SSL Setup Failed: {}\n", .{ret});
            return error.SSLSetupFailed;
        }
    }

    pub fn accept_connection(self: mbedTLS) !void {
        c.mbedtls_net_free(self.client_fd);

        var ret: i32 = undefined;

        ret = c.mbedtls_ssl_session_reset(self.ssl);
        if (ret != 0) {
            std.debug.print("Reset Failed: {}\n", .{ret});
            return error.SSLResetFailed;
        }

        ret = c.mbedtls_net_accept(self.listen_fd, self.client_fd, null, 0, null);
        if (ret != 0) {
            std.debug.print("Accept Failed: {}\n", .{ret});
            return error.SSLAcceptFailed;
        }

        c.mbedtls_ssl_set_bio(self.ssl, self.client_fd, c.mbedtls_net_send, c.mbedtls_net_recv, null);

        while (ret != 0) : (ret = c.mbedtls_ssl_handshake(self.ssl)) {
            if (ret != c.MBEDTLS_ERR_SSL_WANT_READ and ret != c.MBEDTLS_ERR_SSL_WANT_WRITE) {
                std.debug.print("SSL Handshake Failed: {}\n", .{ret});
                return error.SSLHandshakeFailed;
            }
        }
    }

    pub fn read_socket(self: mbedTLS) i32 {
        var ret: i32 = undefined;
        var buffer: [1024]u8 = std.mem.zeroes([1024:0]u8);
        ret = c.mbedtls_ssl_read(self.ssl, &buffer, 1024);
        return ret;
    }

    pub fn write_socket(self: mbedTLS) !i32 {
        var buffer = "Hello, World!";
        var ret: i32 = undefined;
        ret = c.mbedtls_ssl_write(self.ssl, buffer, buffer.len); 
        if (ret <= 0) {
            std.debug.print("SSL Write Failed: {}\n", .{ret});
            return error.SSLWriteFailed;
        }
        var bytes = ret;

        ret = c.mbedtls_ssl_close_notify(self.ssl);
        if (ret < 0) {
            std.debug.print("SSL Close Failed: {}\n", .{ret});
            return error.SSLCloseFailed;
        }

        return bytes;
    }

    pub fn deinit(self: *mbedTLS) void {
        c.mbedtls_net_free(self.client_fd);
        c.mbedtls_net_free(self.listen_fd);

        self.allocator.destroy(self.entropy);
        self.allocator.destroy(self.ctr_drbg);
        self.allocator.destroy(self.ssl);

        c.zmbedtls_ssl_config_free(self.conf);

        self.allocator.destroy(self.srvcrt);
        self.allocator.destroy(self.pkey);
        self.allocator.destroy(self.cache);
        self.* = undefined;
    }
};

pub fn main() !void {
    var allocator = std.heap.c_allocator;

    var mbed = try mbedTLS.init(allocator);
    defer mbed.deinit();

    try mbed.seed();
    try mbed.set_certificate("selfsigned.crt");
    try mbed.set_key("selfsigned.key");

    try mbed.create_socket();

    try mbed.accept_connection();

    var bytes = mbed.read_socket();
    std.debug.print("Read: {any}", .{ bytes });

    bytes = try mbed.write_socket();
    std.debug.print("Write: {any}", .{ bytes });
}
