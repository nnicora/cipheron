package io.github.nnicora.cipheron.internal.client;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Where cipheron listens: a unix socket (a path) or a network address ({@code host:port}), told apart by the address
 * alone ({@code internal/client/options.go}, {@code parseEndpoint}).
 *
 * @param socket the socket's absolute path, or null for a network address
 * @param host the network host, or null for a socket
 * @param port the network port, or 0 for a socket
 */
public record Endpoint(String socket, String host, int port) {
    private static final String UNIX_SCHEME = "unix://";

    /** Whether this is a unix socket. */
    public boolean isSocket() {
        return socket != null;
    }

    /** {@code host:port}, IPv6 hosts in brackets. */
    public String authority() {
        return (host.indexOf(':') >= 0 ? "[" + host + "]" : host) + ":" + port;
    }

    /**
     * Parses {@code address}: {@code unix:///abs/path} or anything holding a {@code /} is a socket path; a
     * {@code host:port} with a host and a port of 1 to 65535 is a network address; a name with no {@code :} is a
     * socket path relative to the working directory; anything else is refused.
     */
    public static Endpoint parse(String address) {
        if (address == null || address.isEmpty()) {
            throw new IllegalArgumentException("cipheron: no address: a socket path or host:port");
        }
        if (address.startsWith(UNIX_SCHEME)) {
            String p = address.substring(UNIX_SCHEME.length());
            if (!p.startsWith("/")) {
                throw new IllegalArgumentException("cipheron: a unix:// address names an absolute path, not \""
                        + p + "\"");
            }
            return socket(p);
        }
        if (address.indexOf('/') >= 0) {
            return socket(address);
        }
        String[] hp = splitHostPort(address);
        if (hp == null) {
            if (address.indexOf(':') < 0) {
                return socket(address);
            }
            throw new IllegalArgumentException("cipheron: \"" + address + "\" is neither a socket path nor host:port");
        }
        int port;
        try {
            port = Integer.parseInt(hp[1]);
        } catch (NumberFormatException e) {
            port = -1;
        }
        if (hp[0].isEmpty() || port < 1 || port > 65535) {
            throw new IllegalArgumentException("cipheron: \"" + address + "\" is neither a socket path nor host:port "
                    + "(a host and a port of 1 to 65535)");
        }
        return new Endpoint(null, hp[0], port);
    }

    /** Whether {@code address} names a unix socket rather than a network address. */
    public static boolean isSocketAddress(String address) {
        try {
            return parse(address).isSocket();
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static Endpoint socket(String p) {
        Path abs = Paths.get(p).toAbsolutePath().normalize();
        return new Endpoint(abs.toString(), null, 0);
    }

    /** Go's net.SplitHostPort: null where it fails. */
    private static String[] splitHostPort(String s) {
        if (s.startsWith("[")) {
            int end = s.indexOf(']');
            if (end < 0 || end + 1 >= s.length() || s.charAt(end + 1) != ':') {
                return null;
            }
            String host = s.substring(1, end);
            String port = s.substring(end + 2);
            if (port.indexOf(':') >= 0 || host.indexOf('[') >= 0) {
                return null;
            }
            return new String[] {host, port};
        }
        int i = s.lastIndexOf(':');
        if (i < 0 || s.indexOf(':') != i || s.indexOf('[') >= 0 || s.indexOf(']') >= 0) {
            return null;
        }
        return new String[] {s.substring(0, i), s.substring(i + 1)};
    }
}
