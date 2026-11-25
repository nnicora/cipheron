package io.github.nnicora.cipheron;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import io.github.nnicora.cipheron.internal.client.Plan;
import io.github.nnicora.cipheron.internal.wire.AssociatedData;
import io.github.nnicora.cipheron.internal.wire.Bytes;
import io.github.nnicora.cipheron.internal.wire.Ciphertexts;
import io.github.nnicora.cipheron.internal.wire.Segmented;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.function.Consumer;

/**
 * The client-side containers built on batches: segmented objects ({@code CPS1}) and their streams, and encrypted
 * JSON fields ({@code cipheron:v1:} and the base64 ciphertext). Segments and fields travel in batches of at most
 * 128 items and 768 KiB, smaller when cipheron's own limits are lower ({@code internal/client/object.go},
 * {@code stream.go}, {@code jsonfields.go}).
 */
final class Containers {
    static final int OBJECT_BATCH_BYTES = 768 << 10;
    static final int OBJECT_BATCH_ITEMS = 128;
    static final int BATCH_FIXED_BYTES = 2 * 2369 + 65;
    static final int MAX_JSON_FIELDS = 4096;
    static final int MAX_RECORD_ID_LEN = 1024;
    static final String JSON_FIELD_PREFIX = "cipheron:v1:";

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().serializeNulls().create();

    private Containers() {}

    /** A batch call: its items in, one result per item out. */
    @FunctionalInterface
    interface Batch {
        List<BatchResult> run(List<BatchItem> items);
    }

    /** An item of a batch that failed alone, with its index. */
    static final class ItemFailure extends RuntimeException {
        private static final long serialVersionUID = 1L;
        final int index;
        final CipheronException error;

        ItemFailure(int index, CipheronException error) {
            super(error.getMessage(), error);
            this.index = index;
            this.error = error;
        }
    }

    static long sealedItemBytes(long plaintext, long aad) {
        return 65 + plaintext + 16 + aad;
    }

    static long itemBytes(BatchItem it, boolean sealed) {
        if (sealed) {
            return sealedItemBytes(len(it.data()), len(it.associatedData()));
        }
        return len(it.data()) + len(it.associatedData()) + len(it.toAssociatedData());
    }

    /** Runs {@code items} through {@code call} in batches that fit, the results in order. */
    static List<byte[]> inBatches(Plan plan, List<BatchItem> items, boolean sealed, Batch call) {
        int maxItems = OBJECT_BATCH_ITEMS;
        long maxBytes = Math.min(OBJECT_BATCH_BYTES, (long) (plan.maxMessage() - Plan.WIRE_OVERHEAD) * 3 / 4);
        List<byte[]> out = new ArrayList<>(items.size());
        int pos = 0;
        while (pos < items.size()) {
            int i = pos;
            int j = pos;
            long size = BATCH_FIXED_BYTES;
            while (j < items.size() && j - i < maxItems && (j == i || size + itemBytes(items.get(j), sealed) <= maxBytes)) {
                size += itemBytes(items.get(j), sealed);
                j++;
            }
            List<BatchResult> res;
            try {
                res = call.run(items.subList(i, j));
            } catch (InvalidInputException e) {
                CipheronException.BatchLimits l = e.batchLimits().orElse(null);
                if (l != null && j - i > 1 && (j - i > l.maxItems() || size > l.maxBytes() * 3 / 4)) {
                    maxItems = l.maxItems();
                    maxBytes = Math.min(l.maxBytes() * 3 / 4, maxBytes);
                    continue;
                }
                throw e;
            }
            for (int k = 0; k < res.size(); k++) {
                if (!res.get(k).ok()) {
                    if (!sealed) {
                        out.forEach(Bytes::wipe);
                    }
                    throw new ItemFailure(i + k, res.get(k).error());
                }
            }
            for (BatchResult r : res) {
                out.add(r.value());
            }
            pos = j;
        }
        return out;
    }

    /** An item's decryption that failed for the data's integrity, not for the key version. */
    static boolean integrityFailure(CipheronException e) {
        return e instanceof InvalidInputException && !(e instanceof KeyVersionUnavailableException);
    }

    static RuntimeException segmentFailure(ItemFailure f, boolean decrypting) {
        if (decrypting && integrityFailure(f.error)) {
            return new SegmentedException("cipheron: not a segmented object, or one that was modified, truncated or "
                    + "reordered: segment " + f.index + ": " + f.error.getMessage(), f.error);
        }
        return f.error;
    }

    static void checkObjectAad(byte[] aad) {
        if (len(aad) > Segmented.MAX_OBJECT_ASSOCIATED_DATA_LEN) {
            throw new AssociatedDataException("cipheron: the associated data does not match the ciphertext's format: "
                    + "an object's associated data is at most " + Segmented.MAX_OBJECT_ASSOCIATED_DATA_LEN + " bytes");
        }
    }

    static int segmentSize(int asked) {
        int size = asked == 0 ? Segmented.DEFAULT_SEGMENT_SIZE : asked;
        if (size < Segmented.MIN_SEGMENT_SIZE || size > Segmented.MAX_SEGMENT_SIZE) {
            throw new InvalidInputException("cipheron: a segment size is " + Segmented.MIN_SEGMENT_SIZE + " to "
                    + Segmented.MAX_SEGMENT_SIZE + " bytes, not " + size);
        }
        return size;
    }

    static void checkSegmentFits(Plan plan, int size, int aadLen) {
        long limit = (long) (plan.maxMessage() - Plan.WIRE_OVERHEAD) * 3 / 4;
        long need = BATCH_FIXED_BYTES + sealedItemBytes(size, aadLen + Segmented.ASSOCIATED_DATA_OVERHEAD);
        if (need > limit) {
            throw new TooLargeException("cipheron: too large: a segment of " + size + " bytes needs a request of "
                    + need + " bytes, and this client's messages carry at most " + limit
                    + " (lower segmentSize, or raise maxMessageBytes)");
        }
    }

    // ── objects ──────────────────────────────────────────────────────────────────────────────────────────

    static byte[] encryptObject(Plan plan, byte[] plaintext, byte[] aad, int segment, Batch call) {
        checkObjectAad(aad);
        int size = segmentSize(segment);
        checkSegmentFits(plan, size, len(aad));
        long count = Math.max(1, ((long) plaintext.length + size - 1) / size);
        if (count > Segmented.MAX_SEGMENTS) {
            throw new TooLargeException("cipheron: too large: " + count + " segments of " + size + " bytes; an object "
                    + "has at most " + Segmented.MAX_SEGMENTS + " (segmentSize)");
        }
        byte[] id = new byte[Segmented.OBJECT_ID_LEN];
        RANDOM.nextBytes(id);
        List<BatchItem> items = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            int lo = i * size;
            int hi = (int) Math.min((long) (i + 1) * size, plaintext.length);
            items.add(new BatchItem(Arrays.copyOfRange(plaintext, lo, hi),
                    AssociatedData.segment(id, i, i == count - 1, aad), null));
        }
        try {
            List<byte[]> segs = inBatches(plan, items, true, call);
            return Segmented.marshal(new Segmented.Header(id, size, (int) count), segs);
        } catch (ItemFailure f) {
            throw segmentFailure(f, false);
        }
    }

    static byte[] decryptObject(Plan plan, byte[] object, byte[] aad, Batch call) {
        checkObjectAad(aad);
        Segmented.Parsed p;
        try {
            p = Segmented.parse(object);
        } catch (Segmented.Refused e) {
            throw new SegmentedException(e.getMessage(), e);
        }
        Segmented.Header h = p.header();
        List<BatchItem> items = new ArrayList<>();
        for (int i = 0; i < p.segments().size(); i++) {
            items.add(new BatchItem(p.segments().get(i),
                    AssociatedData.segment(h.objectId(), i, i == p.segments().size() - 1, aad), null));
        }
        List<byte[]> pts;
        try {
            pts = inBatches(plan, items, false, call);
        } catch (ItemFailure f) {
            throw segmentFailure(f, true);
        }
        long n = 0;
        for (int i = 0; i < pts.size(); i++) {
            checkSegmentLength(h, i, pts.get(i).length, pts);
            n += pts.get(i).length;
        }
        byte[] out = new byte[(int) n];
        int off = 0;
        for (byte[] pt : pts) {
            System.arraycopy(pt, 0, out, off, pt.length);
            off += pt.length;
            Bytes.wipe(pt);
        }
        return out;
    }

    private static void checkSegmentLength(Segmented.Header h, int i, int n, List<byte[]> wipe) {
        boolean last = i == h.count() - 1;
        if ((!last && n != h.segmentSize()) || n > h.segmentSize() || (last && n == 0 && h.count() > 1)) {
            if (wipe != null) {
                wipe.forEach(Bytes::wipe);
            }
            throw new SegmentedException("cipheron: not a segmented object, or one that was modified, truncated or "
                    + "reordered: segment " + i + " holds " + n + " bytes, and the object's segments hold "
                    + h.segmentSize());
        }
    }

    static byte[] reEncryptObject(Plan plan, byte[] object, byte[] aad, byte[] toAad, int segment, Batch call) {
        checkObjectAad(aad);
        checkObjectAad(toAad);
        Segmented.Parsed p;
        try {
            p = Segmented.parse(object);
        } catch (Segmented.Refused e) {
            throw new SegmentedException(e.getMessage(), e);
        }
        Segmented.Header h = p.header();
        if (segment != 0 && segment != h.segmentSize()) {
            throw new InvalidInputException("cipheron: a re-encrypted object keeps its segment size, " + h.segmentSize()
                    + " bytes; segmentSize asks for " + segment);
        }
        List<BatchItem> items = new ArrayList<>();
        for (int i = 0; i < p.segments().size(); i++) {
            byte[] s = p.segments().get(i);
            try {
                Ciphertexts.KeyId kid = Ciphertexts.parse(s);
                checkSegmentLength(h, i, s.length - kid.overhead(), null);
            } catch (Ciphertexts.Refused e) {
                // Not a ciphertext: cipheron refuses it as the item's error.
            }
            boolean last = i == h.count() - 1;
            items.add(new BatchItem(s, AssociatedData.segment(h.objectId(), i, last, aad),
                    AssociatedData.segment(h.objectId(), i, last, toAad)));
        }
        try {
            return Segmented.marshal(h, inBatches(plan, items, false, call));
        } catch (ItemFailure f) {
            throw segmentFailure(f, true);
        }
    }

    // ── streams ──────────────────────────────────────────────────────────────────────────────────────────

    static int group(Plan plan, long perItem) {
        long maxBytes = Math.min(OBJECT_BATCH_BYTES, (long) (plan.maxMessage() - Plan.WIRE_OVERHEAD) * 3 / 4)
                - BATCH_FIXED_BYTES;
        return (int) Math.max(1, Math.min(OBJECT_BATCH_ITEMS, maxBytes / Math.max(1, perItem)));
    }

    static long encryptStream(Plan plan, OutputStream dst, InputStream src, long size, byte[] aad, int segment,
            Batch call) {
        checkObjectAad(aad);
        int seg = segmentSize(segment);
        if (size < 0) {
            throw new InvalidInputException("cipheron: a stream's size is " + size + " bytes");
        }
        checkSegmentFits(plan, seg, len(aad));
        long count = Math.max(1, (size + seg - 1) / seg);
        if (count > Segmented.MAX_SEGMENTS) {
            throw new TooLargeException("cipheron: too large: " + count + " segments of " + seg + " bytes; an object "
                    + "has at most " + Segmented.MAX_SEGMENTS + " (segmentSize)");
        }
        byte[] id = new byte[Segmented.OBJECT_ID_LEN];
        RANDOM.nextBytes(id);
        long written = 0;
        try {
            byte[] header = new Segmented.Header(id, seg, (int) count).bytes();
            dst.write(header);
            written += header.length;
            int group = group(plan, sealedItemBytes(seg, len(aad) + Segmented.ASSOCIATED_DATA_OVERHEAD));
            long read = 0;
            long i = 0;
            while (i < count) {
                long n = Math.min(count - i, group);
                long want = Math.min(n * seg, size - read);
                byte[] buf = src.readNBytes((int) want);
                if (buf.length != want) {
                    throw new InvalidInputException("cipheron: the stream ended before the " + size
                            + " bytes given as its size");
                }
                read += want;
                List<BatchItem> items = new ArrayList<>();
                for (long off = 0; off < want || (want == 0 && items.isEmpty()); off += seg) {
                    items.add(new BatchItem(Arrays.copyOfRange(buf, (int) off, (int) Math.min(off + seg, want)),
                            AssociatedData.segment(id, i, i == count - 1, aad), null));
                    i++;
                }
                List<byte[]> cts;
                try {
                    cts = inBatches(plan, items, true, call);
                } catch (ItemFailure f) {
                    throw segmentFailure(f, false);
                }
                for (byte[] ct : cts) {
                    dst.write(Bytes.uint32(ct.length));
                    dst.write(ct);
                    written += 4 + ct.length;
                }
            }
            if (src.read() >= 0) {
                throw new InvalidInputException("cipheron: the stream holds more than the " + size
                        + " bytes given as its size");
            }
            return written;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static long decryptStream(Plan plan, OutputStream dst, InputStream src, byte[] aad, Batch call) {
        return streamSegments(plan, dst, src, aad, null, false, call, 0);
    }

    static long reEncryptStream(Plan plan, OutputStream dst, InputStream src, byte[] aad, byte[] toAad, int segment,
            Batch call) {
        return streamSegments(plan, dst, src, aad, toAad, true, call, segment);
    }

    private static long streamSegments(Plan plan, OutputStream dst, InputStream src, byte[] aad, byte[] toAad,
            boolean reEncrypt, Batch call, int segment) {
        checkObjectAad(aad);
        if (reEncrypt) {
            checkObjectAad(toAad);
        }
        try {
            Segmented.Header h;
            try {
                h = Segmented.readHeader(src);
            } catch (Segmented.Refused e) {
                throw new SegmentedException(e.getMessage(), e);
            }
            if (reEncrypt && segment != 0 && segment != h.segmentSize()) {
                throw new InvalidInputException("cipheron: a re-encrypted object keeps its segment size, "
                        + h.segmentSize() + " bytes; segmentSize asks for " + segment);
            }
            long written = 0;
            if (reEncrypt) {
                byte[] header = h.bytes();
                dst.write(header);
                written += header.length;
            }
            int group = group(plan, (long) h.segmentSize() + 98 + 2L * Segmented.ASSOCIATED_DATA_OVERHEAD + len(aad)
                    + len(toAad));
            int i = 0;
            while (i < h.count()) {
                int start = i;
                List<BatchItem> items = new ArrayList<>();
                for (; i < h.count() && items.size() < group; i++) {
                    byte[] s;
                    try {
                        s = Segmented.readSegment(src, h);
                    } catch (Segmented.Refused e) {
                        throw new SegmentedException(e.getMessage(), e);
                    }
                    boolean last = i == h.count() - 1;
                    items.add(new BatchItem(s, AssociatedData.segment(h.objectId(), i, last, aad),
                            reEncrypt ? AssociatedData.segment(h.objectId(), i, last, toAad) : null));
                }
                List<byte[]> outs;
                try {
                    outs = inBatches(plan, items, false, call);
                } catch (ItemFailure f) {
                    throw segmentFailure(new ItemFailure(start + f.index, f.error), true);
                }
                for (int k = 0; k < outs.size(); k++) {
                    byte[] o = outs.get(k);
                    if (reEncrypt) {
                        dst.write(Bytes.uint32(o.length));
                        dst.write(o);
                        written += 4 + o.length;
                    } else {
                        checkSegmentLength(h, start + k, o.length, outs);
                        dst.write(o);
                        written += o.length;
                        Bytes.wipe(o);
                    }
                }
            }
            if (src.read() >= 0) {
                throw new SegmentedException("cipheron: not a segmented object, or one that was modified, truncated or "
                        + "reordered: bytes after its last segment");
            }
            return written;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // ── JSON fields ──────────────────────────────────────────────────────────────────────────────────────

    enum FieldOp { ENCRYPT, DECRYPT, RE_ENCRYPT }

    static List<String> parsePointer(String p) {
        if (p.isEmpty() || p.charAt(0) != '/') {
            throw jsonField("\"" + p + "\" is not a JSON Pointer to a field (\"/a/b\", RFC 6901)");
        }
        List<String> out = new ArrayList<>();
        for (String t : p.substring(1).split("/", -1)) {
            for (int j = 0; j < t.length(); j++) {
                if (t.charAt(j) == '~' && (j + 1 == t.length() || (t.charAt(j + 1) != '0' && t.charAt(j + 1) != '1'))) {
                    throw jsonField("\"" + p + "\": a \"~\" is written ~0, a \"/\" ~1");
                }
            }
            out.add(t.replace("~1", "/").replace("~0", "~"));
        }
        return out;
    }

    static JsonFieldException jsonField(String why) {
        return new JsonFieldException("cipheron: not a JSON document, field or encrypted field the call can use: " + why);
    }

    /** A located value: what is there, and how to replace it. */
    record Slot(JsonElement value, Consumer<JsonElement> set) {}

    static Slot locate(JsonElement doc, List<String> tokens) {
        JsonElement cur = doc;
        for (int k = 0; k < tokens.size(); k++) {
            String tok = tokens.get(k);
            boolean last = k == tokens.size() - 1;
            if (cur.isJsonObject()) {
                JsonObject o = cur.getAsJsonObject();
                if (!o.has(tok)) {
                    return null;
                }
                if (last) {
                    return new Slot(o.get(tok), x -> o.add(tok, x));
                }
                cur = o.get(tok);
            } else if (cur.isJsonArray()) {
                JsonArray a = cur.getAsJsonArray();
                int i = arrayIndex(tok, a.size());
                if (i < 0) {
                    return null;
                }
                if (last) {
                    return new Slot(a.get(i), x -> a.set(i, x));
                }
                cur = a.get(i);
            } else {
                return null;
            }
        }
        return null;
    }

    private static int arrayIndex(String tok, int n) {
        if (tok.isEmpty() || (tok.length() > 1 && tok.charAt(0) == '0')) {
            return -1;
        }
        for (int i = 0; i < tok.length(); i++) {
            if (!Character.isDigit(tok.charAt(i))) {
                return -1;
            }
        }
        try {
            int i = Integer.parseInt(tok);
            return i < n ? i : -1;
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /** Exactly one JSON value, numbers kept as written. */
    static JsonElement decode(String s) {
        try {
            JsonReader r = new JsonReader(new StringReader(s));
            r.setStrictness(Strictness.STRICT);
            JsonElement v = com.google.gson.internal.Streams.parse(r);
            if (r.peek() != JsonToken.END_DOCUMENT) {
                throw new JsonParseException("more than one JSON value");
            }
            return v;
        } catch (IOException | JsonParseException | IllegalStateException e) {
            throw jsonField("the document: " + e.getMessage());
        }
    }

    static byte[] fieldAad(String recordId, String pointer, byte[] aad, String which) {
        byte[] ad = AssociatedData.jsonField(recordId, pointer, aad);
        if (ad.length > Ciphertexts.MAX_ASSOCIATED_DATA_LEN) {
            throw jsonField("\"" + pointer + "\": the field's " + which + "associated data is " + ad.length
                    + " bytes; at most " + Ciphertexts.MAX_ASSOCIATED_DATA_LEN);
        }
        return ad;
    }

    static byte[] jsonFields(Plan plan, byte[] doc, String recordId, List<String> pointers, byte[] aad, byte[] toAad,
            FieldOp op, Batch call) {
        if (recordId == null || recordId.isEmpty() || Bytes.utf8(recordId).length > MAX_RECORD_ID_LEN) {
            throw jsonField("a record id is 1 to " + MAX_RECORD_ID_LEN + " bytes of UTF-8");
        }
        if (pointers.isEmpty() || pointers.size() > MAX_JSON_FIELDS) {
            throw jsonField("1 to " + MAX_JSON_FIELDS + " field pointers, not " + pointers.size());
        }
        List<List<String>> paths = new ArrayList<>();
        for (String p : pointers) {
            paths.add(parsePointer(p));
        }
        for (int i = 0; i < paths.size(); i++) {
            for (int j = 0; j < paths.size(); j++) {
                List<String> a = paths.get(i);
                List<String> b = paths.get(j);
                if (i != j && a.size() <= b.size() && a.equals(b.subList(0, a.size()))) {
                    throw jsonField("\"" + pointers.get(i) + "\" and \"" + pointers.get(j) + "\": a field is named "
                            + "twice, or inside another");
                }
            }
        }
        JsonElement root = decode(new String(doc, StandardCharsets.UTF_8));
        List<BatchItem> items = new ArrayList<>();
        List<Slot> slots = new ArrayList<>();
        for (int i = 0; i < paths.size(); i++) {
            Slot s = locate(root, paths.get(i));
            String ptr = pointers.get(i);
            if (s == null) {
                throw jsonField("\"" + ptr + "\" names no value of the document");
            }
            byte[] ad = fieldAad(recordId, ptr, aad, "");
            byte[] toAd = op == FieldOp.RE_ENCRYPT ? fieldAad(recordId, ptr, toAad, "target ") : null;
            byte[] data;
            if (op == FieldOp.ENCRYPT) {
                if (isField(s.value())) {
                    throw jsonField("\"" + ptr + "\" is encrypted already");
                }
                data = Bytes.utf8(GSON.toJson(s.value()));
            } else {
                if (!s.value().isJsonPrimitive() || !s.value().getAsJsonPrimitive().isString()) {
                    throw jsonField("\"" + ptr + "\" is not an encrypted field");
                }
                data = decodeField(s.value().getAsString(), ptr);
            }
            items.add(new BatchItem(data, ad, toAd));
            slots.add(s);
        }
        List<byte[]> out;
        try {
            out = inBatches(plan, items, op == FieldOp.ENCRYPT, call);
        } catch (ItemFailure f) {
            CipheronException e = f.error;
            e.addSuppressed(new IllegalStateException("cipheron: field \"" + pointers.get(f.index) + "\""));
            throw e;
        }
        for (int i = 0; i < out.size(); i++) {
            byte[] v = out.get(i);
            if (op != FieldOp.DECRYPT) {
                slots.get(i).set().accept(new JsonPrimitive(JSON_FIELD_PREFIX + Base64.getEncoder().encodeToString(v)));
                continue;
            }
            JsonElement x;
            try {
                x = decode(new String(v, StandardCharsets.UTF_8));
            } catch (JsonFieldException e) {
                throw jsonField("\"" + pointers.get(i) + "\" decrypted to something that is not one JSON value");
            }
            slots.get(i).set().accept(x);
        }
        return Bytes.utf8(GSON.toJson(root));
    }

    static boolean isField(JsonElement v) {
        return v.isJsonPrimitive() && v.getAsJsonPrimitive().isString()
                && v.getAsString().startsWith(JSON_FIELD_PREFIX);
    }

    static byte[] decodeField(String v, String pointer) {
        if (!v.startsWith(JSON_FIELD_PREFIX) || v.length() == JSON_FIELD_PREFIX.length()) {
            throw jsonField("\"" + pointer + "\" is not an encrypted field");
        }
        try {
            String body = v.substring(JSON_FIELD_PREFIX.length());
            byte[] ct = Base64.getDecoder().decode(body);
            if (!Base64.getEncoder().encodeToString(ct).equals(body)) {
                throw new IllegalArgumentException("not canonical base64");
            }
            return ct;
        } catch (IllegalArgumentException e) {
            throw jsonField("\"" + pointer + "\" is not an encrypted field");
        }
    }

    static int len(byte[] b) {
        return b == null ? 0 : b.length;
    }
}
