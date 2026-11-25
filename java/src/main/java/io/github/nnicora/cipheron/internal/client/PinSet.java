package io.github.nnicora.cipheron.internal.client;

import java.util.List;
import java.util.Map;

/**
 * The pins in force at a moment: profile fingerprints, key-context digests and writer versions. A set is immutable;
 * the pins directory replaces it whole, and the keys a client caches remember the set they were checked under.
 *
 * @param fingerprints profile → fingerprint
 * @param context profile → the key-context digests it accepts
 * @param writers profile → the master versions its writer may use
 */
record PinSet(Map<String, String> fingerprints, Map<String, List<String>> context,
        Map<String, List<String>> writers) {
    PinSet {
        fingerprints = Map.copyOf(fingerprints);
        context = Map.copyOf(context);
        writers = Map.copyOf(writers);
    }

    String fingerprint(String profile) {
        return fingerprints.get(profile);
    }

    List<String> contextDigests(String profile) {
        return context.get(profile);
    }

    List<String> writerVersions(String profile) {
        return writers.get(profile);
    }
}
