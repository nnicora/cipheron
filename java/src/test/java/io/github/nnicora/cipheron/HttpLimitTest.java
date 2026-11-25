package io.github.nnicora.cipheron;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

/** An answer over the JSON API larger than the client reads (maxMessageBytes) is refused as too large, unread. */
class HttpLimitTest {
    @Test
    void anAnswerLargerThanTheClientReadsIsTooLarge() throws Exception {
        // A short directory: a socket path is at most 104 bytes on macOS.
        Path dir = Files.createTempDirectory(Path.of("/tmp"), "cph");
        Path sock = dir.resolve("h.sock");
        try (ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            server.bind(UnixDomainSocketAddress.of(sock));
            Thread t = new Thread(() -> answerHuge(server));
            t.setDaemon(true);
            t.start();
            // A client reading at most 4096 bytes of message: 4096 / 3 * 4 + 64 KiB of JSON.
            try (CipheronClient c = CipheronClient.builder(sock.toString()).anyServer().transport(Transport.HTTP)
                    .maxMessageBytes(4096).defaultTimeout(Duration.ofSeconds(10)).build()) {
                assertThrows(TooLargeException.class,
                        () -> c.encrypt("ledger", "x".getBytes(StandardCharsets.UTF_8)));
            }
        } finally {
            Files.deleteIfExists(sock);
            Files.deleteIfExists(dir);
        }
    }

    /** Reads one request's head and answers 200 with a 256 KiB body. */
    private static void answerHuge(ServerSocketChannel server) {
        try (SocketChannel c = server.accept()) {
            ByteBuffer in = ByteBuffer.allocate(64 << 10);
            String head = "";
            while (!head.contains("\r\n\r\n") && c.read(in) > 0) {
                head = new String(in.array(), 0, in.position(), StandardCharsets.ISO_8859_1);
            }
            byte[] body = new byte[256 << 10];
            Arrays.fill(body, (byte) 'a');
            c.write(ByteBuffer.wrap(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                    + body.length + "\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1)));
            ByteBuffer out = ByteBuffer.wrap(body);
            while (out.hasRemaining() && c.write(out) >= 0) {
                // The client closes as soon as it has read past its bound.
            }
        } catch (IOException e) {
            // The client closed the connection: what it does once the answer passes its bound.
        }
    }
}
