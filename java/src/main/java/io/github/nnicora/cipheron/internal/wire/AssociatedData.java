package io.github.nnicora.cipheron.internal.wire;

/**
 * The associated data the client-side containers bind each encryption to: a segment of a segmented object
 * ({@code wire/transport/segment.go}) and an encrypted JSON field ({@code jsonfield.go}).
 */
public final class AssociatedData {
    private AssociatedData() {}

    /**
     * What segment {@code index} of an object is encrypted with: {@code lp("cipheron/v1|segment") lp(object id)
     * lp(u32(index)) lp(final: 0x01 for the last segment, else 0x00) lp(caller associated data)}.
     */
    public static byte[] segment(byte[] objectId, long index, boolean last, byte[] aad) {
        return Lp.create().add(Labels.SEGMENT).add(objectId).addUint32(index).add(new byte[] {(byte) (last ? 1 : 0)})
                .add(aad).bytes();
    }

    /**
     * What an encrypted JSON field is encrypted with: {@code lp("cipheron/v1|json-field") lp(record id)
     * lp(JSON pointer) lp(caller associated data)}.
     */
    public static byte[] jsonField(String recordId, String pointer, byte[] aad) {
        return Lp.create().add(Labels.JSON_FIELD).add(recordId).add(pointer).add(aad).bytes();
    }
}
