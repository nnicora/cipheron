package io.github.nnicora.cipheron.conformance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.github.nnicora.cipheron.RepoFiles;

import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.junit.jupiter.api.Test;

/**
 * Every case of the conformance kit ({@code spec/vectors/cipheron-conformance-v1.json}) computed by this library and
 * compared, as a JSON value, with the case's output. The Go runner holds the adapter to the same file
 * ({@code make java-conformance}); this test is the quick loop.
 */
class ConformanceVectorsTest {
    @Test
    void everyCaseOfTheKitPasses() throws IOException {
        JsonObject suite = JsonParser
                .parseString(Files.readString(RepoFiles.path("spec/vectors/cipheron-conformance-v1.json")))
                .getAsJsonObject();
        assertEquals("cipheron-conformance/v1", suite.get("schema").getAsString());
        assertEquals(1, suite.get("transcriptVersion").getAsInt());

        Map<String, int[]> perKind = new TreeMap<>();
        List<String> failures = new ArrayList<>();
        int n = 0;
        for (JsonElement e : suite.getAsJsonArray("cases")) {
            JsonObject c = e.getAsJsonObject();
            String kind = c.get("kind").getAsString();
            int[] counts = perKind.computeIfAbsent(kind, k -> new int[2]);
            n++;
            JsonElement want = c.get("output");
            JsonElement got;
            try {
                got = ConformanceEvaluator.evaluate(kind, c.getAsJsonObject("input"));
            } catch (ConformanceEvaluator.BadInput ex) {
                failures.add(c.get("id").getAsString() + " (" + kind + "): error " + ex.getMessage());
                counts[1]++;
                continue;
            }
            if (got == null || !got.equals(want)) {
                failures.add(c.get("id").getAsString() + " (" + kind + "): want " + want + ", got " + got);
                counts[1]++;
            } else {
                counts[0]++;
            }
        }
        StringBuilder report = new StringBuilder();
        perKind.forEach((k, v) -> report.append(String.format("%-26s %3d passed %3d failed%n", k, v[0], v[1])));
        assertTrue(failures.isEmpty(), report + "\n" + String.join("\n", failures));
        assertEquals(259, n, "the kit's case count");
        assertEquals(20, perKind.size(), "the kit's kind count");
    }
}
