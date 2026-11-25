package io.github.nnicora.cipheron.internal.client;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;

import java.io.IOException;
import java.nio.channels.SocketChannel;
import java.nio.file.FileSystems;
import java.nio.file.attribute.UserPrincipal;
import java.util.Set;

import jdk.net.ExtendedSocketOptions;
import jdk.net.UnixDomainPrincipal;

/**
 * The unix socket's server check: before a byte is written on a new connection, the user of the process at the other
 * end must be the expected uid, else the connection is closed and the waiting calls fail at once as an identity
 * failure ({@code internal/client/dial.go}, {@code checkServerUID}). The peer is read by the JDK
 * ({@code SO_PEERCRED}: SO_PEERCRED on Linux, LOCAL_PEERCRED on macOS) on the connection's own socket, and this is the
 * first handler of its pipeline, so gRPC's handlers see the connection only once it passed.
 */
final class PeerCheck extends ChannelInboundHandlerAdapter {
    /**
     * The uids that name no one in particular, refused as a server's ({@code peercred/ids.go}): root, nobody and the
     * kernel's overflow uid, and the two values that mean "no uid".
     */
    static final Set<Long> REFUSED_IDS = Set.of(0L, 65534L, 4294967294L, 4294967295L);

    private final String path;
    private final long expected;
    private final SocketChannel socket;
    private final IdentityState id;

    PeerCheck(String path, long expected, SocketChannel socket, IdentityState id) {
        this.path = path;
        this.expected = expected;
        this.socket = socket;
        this.id = id;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        UnixDomainPrincipal peer;
        UserPrincipal want;
        try {
            peer = socket.getOption(ExtendedSocketOptions.SO_PEERCRED);
            want = FileSystems.getDefault().getUserPrincipalLookupService()
                    .lookupPrincipalByName(Long.toString(expected));
        } catch (IOException | UnsupportedOperationException e) {
            refuse(ctx, "cipheron: the credentials of the process serving " + path + " cannot be read: "
                    + e.getMessage());
            return;
        }
        if (!peer.user().equals(want)) {
            refuse(ctx, "cipheron: the process serving " + path + " runs as user " + peer.user().getName()
                    + ", not the expected uid " + expected + ": refusing to talk to it");
            return;
        }
        id.clear();
        ctx.pipeline().remove(this);
        super.channelActive(ctx);
    }

    private void refuse(ChannelHandlerContext ctx, String why) {
        id.failed(new IllegalStateException(why));
        ctx.close();
    }
}
