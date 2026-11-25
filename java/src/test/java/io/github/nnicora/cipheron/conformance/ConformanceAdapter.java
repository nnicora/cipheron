package io.github.nnicora.cipheron.conformance;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

/**
 * The conformance kit's adapter protocol ({@code conformance/conformance.go}): one JSON case per line on standard
 * input, one answer per line on standard output — {@code {"id","output"}}, {@code {"id","error"}} or
 * {@code {"id","unsupported":true}} — each answered before the next is read; the program exits when its input closes.
 * The Go runner ({@code java/harness conformance}) drives it.
 */
public final class ConformanceAdapter {
    private ConformanceAdapter() {}

    public static void main(String[] args) throws IOException {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        PrintStream out = new PrintStream(System.out, false, StandardCharsets.UTF_8);
        String line;
        while ((line = in.readLine()) != null) {
            if (line.isBlank()) {
                continue;
            }
            JsonObject c = JsonParser.parseString(line).getAsJsonObject();
            JsonObject answer = new JsonObject();
            answer.add("id", c.get("id"));
            try {
                JsonObject output = ConformanceEvaluator.evaluate(c.get("kind").getAsString(),
                        c.get("input").getAsJsonObject());
                if (output == null) {
                    answer.addProperty("unsupported", true);
                } else {
                    answer.add("output", output);
                }
            } catch (ConformanceEvaluator.BadInput | RuntimeException e) {
                answer.addProperty("error", String.valueOf(e.getMessage()));
            }
            out.println(answer);
            out.flush();
        }
    }
}
