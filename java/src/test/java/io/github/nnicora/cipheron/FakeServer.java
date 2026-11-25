package io.github.nnicora.cipheron;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

/**
 * cipherontest's fake cipheron, served by the Go harness ({@code java/harness fake}) as a process of its own: the
 * Java tests talk to it over the gRPC socket, the HTTP socket and mutual TLS, and steer it (impostor modes, faults,
 * rotations) over its standard input. The harness is built once per run with the Go toolchain; without Go the tests
 * that need it are skipped.
 */
final class FakeServer implements AutoCloseable {
    private static Path binary;

    private final Process process;
    private final BufferedReader out;
    private final Writer in;
    final JsonObject ready;

    private FakeServer(Process process) throws IOException {
        this.process = process;
        this.out = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
        this.in = new OutputStreamWriter(process.getOutputStream(), StandardCharsets.UTF_8);
        String line = out.readLine();
        if (line == null) {
            throw new IOException("the fake exited before it served");
        }
        this.ready = JsonParser.parseString(line).getAsJsonObject();
    }

    /** Starts a fake serving {@code profiles} ({@code name[:shared|wrapped|derived]}, comma-separated). */
    static FakeServer start(String profiles) throws IOException, InterruptedException {
        Process p = new ProcessBuilder(harness().toString(), "fake", "-profiles", profiles)
                .redirectError(ProcessBuilder.Redirect.INHERIT).start();
        return new FakeServer(p);
    }

    private static synchronized Path harness() throws IOException, InterruptedException {
        if (binary != null) {
            return binary;
        }
        String given = System.getProperty("cipheron.harness");
        if (given != null && !given.isEmpty()) {
            binary = Path.of(given);
            return binary;
        }
        Path root = RepoFiles.root();
        Path target = root.resolve("java/target/harness");
        Process go;
        try {
            go = new ProcessBuilder("go", "build", "-o", target.toString(), "./java/harness").directory(root.toFile())
                    .redirectErrorStream(true).start();
        } catch (IOException e) {
            assumeTrue(false, "no Go toolchain to build the fake: " + e.getMessage());
            throw e;
        }
        String log = new String(go.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!go.waitFor(5, TimeUnit.MINUTES) || go.exitValue() != 0 || !Files.isExecutable(target)) {
            throw new IOException("building the harness failed: " + log);
        }
        binary = target;
        return binary;
    }

    String socket() {
        return ready.get("socket").getAsString();
    }

    String httpSocket() {
        return ready.get("httpSocket").getAsString();
    }

    String tls() {
        return ready.get("tls").getAsString();
    }

    /** The JSON API over mutual TLS. */
    String httpTls() {
        return ready.get("httpTls").getAsString();
    }

    String serverId() {
        return ready.get("serverId").getAsString();
    }

    /** Makes both TLS listeners refuse every client certificate in the handshake (or admit them again). */
    void refuseCertificates(boolean refuse) throws IOException {
        JsonObject c = new JsonObject();
        c.addProperty("op", "refuseCertificates");
        c.addProperty("n", refuse ? 1 : 0);
        send(c);
    }

    Path file(String name) {
        return Path.of(ready.get(name).getAsString());
    }

    long uid() {
        return ready.get("uid").getAsLong();
    }

    String fingerprint(String profile) {
        return ready.getAsJsonObject("profiles").getAsJsonObject(profile).get("fingerprint").getAsString();
    }

    String contextDigest(String profile) {
        return ready.getAsJsonObject("profiles").getAsJsonObject(profile).get("contextDigest").getAsString();
    }

    /** Sends one control command and answers its result: {@code {"op":…, …}}. */
    synchronized JsonElement send(JsonObject command) throws IOException {
        in.write(command + "\n");
        in.flush();
        String line = out.readLine();
        if (line == null) {
            throw new IOException("the fake exited");
        }
        JsonObject r = JsonParser.parseString(line).getAsJsonObject();
        if (r.has("error")) {
            throw new IOException("fake: " + r.get("error").getAsString());
        }
        return r.get("ok");
    }

    /** Sends {@code op} with string arguments given as name, value pairs. */
    JsonElement op(String op, String... args) throws IOException {
        JsonObject c = new JsonObject();
        c.addProperty("op", op);
        for (int i = 0; i + 1 < args.length; i += 2) {
            c.addProperty(args[i], args[i + 1]);
        }
        return send(c);
    }

    @Override
    public void close() throws IOException {
        in.close();
        try {
            if (!process.waitFor(10, TimeUnit.SECONDS)) {
                process.destroyForcibly();
            }
        } catch (InterruptedException e) {
            process.destroyForcibly();
            Thread.currentThread().interrupt();
        }
    }
}
