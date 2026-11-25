package io.github.nnicora.cipheron;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * A JSON-field document is written back byte for byte as the Go library writes it ({@code encodeJSON} in
 * {@code internal/client/jsonfields.go}: {@code encoding/json}, HTML escaping off). Each expected output below is what
 * Go 1.27 printed for the input. In the inputs, {@code §} stands for a backslash, so this file names no character by
 * a Java escape.
 */
class JsonEncodingTest {
    private static String json(String s) {
        return s.replace('§', '\\');
    }

    private static String cp(int codePoint) {
        return new String(Character.toChars(codePoint));
    }

    private static void same(String input, String go) {
        assertEquals(go, Containers.encode(Containers.decode(input)), input);
    }

    @Test
    void objectKeysAreSortedAndTheDocumentIsCompact() {
        same("{\"z\":1,\"a\":{\"y\":[1,2,{\"c\":null,\"b\":false}],\"x\":\"<&>\"}}",
                "{\"a\":{\"x\":\"<&>\",\"y\":[1,2,{\"b\":false,\"c\":null}]},\"z\":1}");
        same(" [ " + json("\"§u00e9§ud83d§ude00\"") + " , {} , [] ] ", "[\"" + cp(0xe9) + cp(0x1f600) + "\",{},[]]");
    }

    @Test
    void keysSortByCodePointAsUtf8BytesDo() {
        // UTF-16 order (String.compareTo) would put U+1F600 before U+FFFF.
        same(json("{\"§uffff\":1,\"§ud83d§ude00\":2,\"~\":3,\"§u00e9\":4,\"\":5}"),
                "{\"\":5,\"~\":3,\"" + cp(0xe9) + "\":4,\"" + cp(0xffff) + "\":1,\"" + cp(0x1f600) + "\":2}");
        assertTrue(Containers.compareCodePoints(cp(0xffff), cp(0x1f600)) < 0);
    }

    @Test
    void aRepeatedKeyKeepsItsLastValue() {
        same("{\"a\":1,\"a\":2}", "{\"a\":2}");
    }

    @Test
    void numbersStayAsWritten() {
        same("[1e5,-0.0,12345678901234567890123,0.10,-1E-7]", "[1e5,-0.0,12345678901234567890123,0.10,-1E-7]");
    }

    @Test
    void stringsAreEscapedAsGoEscapesThem() {
        same(json("\"§b§f§n§r§t§u0001§u001f§u007f§u2028§u2029 §\"§§ §/\""),
                json("\"§b§f§n§r§t§u0001§u001f") + cp(0x7f) + json("§u2028§u2029 §\"§§ /\""));
    }

    @Test
    void anUnpairedSurrogateBecomesTheReplacementCharacter() {
        same(json("\"§ud800x§udc00\""), "\"" + cp(0xfffd) + "x" + cp(0xfffd) + "\"");
    }
}
