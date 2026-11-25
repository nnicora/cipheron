package io.github.nnicora.cipheron.internal.wire;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Segmented objects ({@code CPS1}): a client-side container of ciphertexts, one per segment, each bound to its object
 * and position by its associated data ({@link AssociatedData#segment}), so no segment can be dropped, reordered or
 * moved to another object ({@code wire/transport/segment.go}).
 *
 * <pre>
 * "CPS1" | 0x01 | object id (16) | segment size (u32) | count (u32) | count × (u32 length | ciphertext)
 * </pre>
 */
public final class Segmented {
    public static final byte[] MAGIC = {'C', 'P', 'S', '1'};
    public static final int VERSION = 1;
    public static final int OBJECT_ID_LEN = 16;
    public static final int HEADER_LEN = MAGIC.length + 1 + OBJECT_ID_LEN + 4 + 4;
    public static final int MIN_SEGMENT_SIZE = 1 << 10;
    public static final int MAX_SEGMENT_SIZE = 16 << 20;
    public static final int DEFAULT_SEGMENT_SIZE = 64 << 10;
    public static final int MAX_SEGMENTS = 1 << 20;

    /** A streamed segment may be at most this much longer than the segment size (its header, nonce, tag). */
    public static final int MAX_SEGMENT_OVERHEAD = 1 << 10;

    /** The bytes a segment's associated data adds to the caller's. */
    public static final int ASSOCIATED_DATA_OVERHEAD = 60;

    /** The longest caller associated data of an object: a segment's own fits in 64 KiB with it. */
    public static final int MAX_OBJECT_ASSOCIATED_DATA_LEN = Ciphertexts.MAX_ASSOCIATED_DATA_LEN
            - ASSOCIATED_DATA_OVERHEAD;

    private Segmented() {}

    /**
     * An object's header.
     *
     * @param objectId the object's random id
     * @param segmentSize the plaintext bytes of every segment but the last
     * @param count the number of segments
     */
    public record Header(byte[] objectId, int segmentSize, int count) {
        /** Whether the header's fields are within their bounds. */
        boolean valid() {
            return objectId.length == OBJECT_ID_LEN && segmentSize >= MIN_SEGMENT_SIZE && segmentSize <= MAX_SEGMENT_SIZE
                    && count >= 1 && count <= MAX_SEGMENTS;
        }

        /** The header's bytes. */
        public byte[] bytes() {
            ByteArrayOutputStream out = new ByteArrayOutputStream(HEADER_LEN);
            out.writeBytes(MAGIC);
            out.write(VERSION);
            out.writeBytes(objectId);
            out.writeBytes(Bytes.uint32(segmentSize));
            out.writeBytes(Bytes.uint32(count));
            return out.toByteArray();
        }
    }

    /** A refusal: not a segmented object, or one that was modified, truncated or reordered. */
    public static final class Refused extends Exception {
        private static final long serialVersionUID = 1L;

        public Refused() {
            super("cipheron: not a segmented object, or one that was modified, truncated or reordered");
        }
    }

    /** {@code h} and its segments, framed. */
    public static byte[] marshal(Header h, List<byte[]> segments) {
        if (!h.valid() || h.count() != segments.size()) {
            throw new IllegalArgumentException("cipheron: a segmented object's header does not fit its segments");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(h.bytes());
        for (byte[] s : segments) {
            out.writeBytes(Bytes.uint32(s.length));
            out.writeBytes(s);
        }
        return out.toByteArray();
    }

    private static Header header(byte[] b) throws Refused {
        if (b.length < HEADER_LEN || !Arrays.equals(b, 0, MAGIC.length, MAGIC, 0, MAGIC.length)
                || (b[MAGIC.length] & 0xff) != VERSION) {
            throw new Refused();
        }
        int off = MAGIC.length + 1;
        byte[] id = Arrays.copyOfRange(b, off, off + OBJECT_ID_LEN);
        long size = Bytes.uint32(b, off + OBJECT_ID_LEN);
        long count = Bytes.uint32(b, off + OBJECT_ID_LEN + 4);
        if (size > MAX_SEGMENT_SIZE || count > MAX_SEGMENTS) {
            throw new Refused();
        }
        Header h = new Header(id, (int) size, (int) count);
        if (!h.valid()) {
            throw new Refused();
        }
        return h;
    }

    /** An object parsed: its header and its segments, every byte accounted for. */
    public record Parsed(Header header, List<byte[]> segments) {}

    /** Parses a whole object. */
    public static Parsed parse(byte[] b) throws Refused {
        Header h = header(b);
        int p = HEADER_LEN;
        if ((long) h.count() * 4 > b.length - p) {
            throw new Refused();
        }
        List<byte[]> segs = new ArrayList<>(h.count());
        for (int i = 0; i < h.count(); i++) {
            if (b.length - p < 4) {
                throw new Refused();
            }
            long n = Bytes.uint32(b, p);
            p += 4;
            if (n > b.length - p) {
                throw new Refused();
            }
            segs.add(Arrays.copyOfRange(b, p, p + (int) n));
            p += (int) n;
        }
        if (p != b.length) {
            throw new Refused();
        }
        return new Parsed(h, segs);
    }

    /** Reads an object's header from a stream. */
    public static Header readHeader(InputStream in) throws IOException, Refused {
        return header(readFully(in, HEADER_LEN));
    }

    /** Reads the next segment from a stream: at most the segment size and its overhead. */
    public static byte[] readSegment(InputStream in, Header h) throws IOException, Refused {
        long n = Bytes.uint32(readFully(in, 4), 0);
        if (n > (long) h.segmentSize() + MAX_SEGMENT_OVERHEAD) {
            throw new Refused();
        }
        return readFully(in, (int) n);
    }

    private static byte[] readFully(InputStream in, int n) throws IOException, Refused {
        byte[] b = in.readNBytes(n);
        if (b.length != n) {
            throw new Refused();
        }
        return b;
    }
}
