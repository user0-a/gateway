package com.wwgateway.verifier;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class VectorSuiteTest {
    @Test
    void javaVerifierMatchesPythonReference() throws Exception {
        List<String> failures = VectorSuite.run(Path.of("src/test/resources/vectors.json"));
        assertEquals(List.of(), failures);
    }
}
