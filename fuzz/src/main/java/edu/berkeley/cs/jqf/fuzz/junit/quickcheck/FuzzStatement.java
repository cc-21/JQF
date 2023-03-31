/*
 * Copyright (c) 2017-2018 The Regents of the University of California
 * Copyright (c) 2020-2021 Rohan Padhye
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package edu.berkeley.cs.jqf.fuzz.junit.quickcheck;

import com.pholser.junit.quickcheck.generator.GenerationStatus;
import com.pholser.junit.quickcheck.generator.Generator;
import com.pholser.junit.quickcheck.internal.ParameterTypeContext;
import com.pholser.junit.quickcheck.internal.generator.GeneratorRepository;
import com.pholser.junit.quickcheck.random.SourceOfRandomness;
import edu.berkeley.cs.jqf.fuzz.afl.AFLGuidance;
import edu.berkeley.cs.jqf.fuzz.ei.ZestGuidance;
import edu.berkeley.cs.jqf.fuzz.guidance.*;
import edu.berkeley.cs.jqf.fuzz.util.InputStreamAFL;
import edu.berkeley.cs.jqf.fuzz.util.SyntaxException;
import edu.berkeley.cs.jqf.instrument.InstrumentationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.collections.impl.map.mutable.primitive.IntIntHashMap;
import org.junit.AssumptionViolatedException;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.MultipleFailureException;
import org.junit.runners.model.Statement;
import org.junit.runners.model.TestClass;
import org.w3c.dom.Document;
import ru.vyarus.java.generics.resolver.GenericsResolver;
import ru.vyarus.java.generics.resolver.context.MethodGenericsContext;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.EOFException;
import java.io.IOException;
import java.io.StringWriter;
import java.lang.reflect.Parameter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static edu.berkeley.cs.jqf.fuzz.guidance.Result.*;

/**
 * A JUnit {@link Statement} that will be run using guided fuzz
 * testing.
 *
 * @author Rohan Padhye
 */
public class FuzzStatement extends Statement {
    private final FrameworkMethod method;
    private final TestClass testClass;
    private final MethodGenericsContext generics;
    private final GeneratorRepository generatorRepository;
    private final List<Class<?>> expectedExceptions;
    private final List<Throwable> failures = new ArrayList<>();
    private final Guidance guidance;
    private boolean skipExceptionSwallow;
    private static final Logger logger = LogManager.getLogger(FuzzStatement.class);

    public FuzzStatement(FrameworkMethod method, TestClass testClass,
                         GeneratorRepository generatorRepository, Guidance fuzzGuidance) throws IOException {
        this.method = method;
        this.testClass = testClass;
        this.generics = GenericsResolver.resolve(testClass.getJavaClass())
                .method(method.getMethod());
        this.generatorRepository = generatorRepository;
        this.expectedExceptions = Arrays.asList(method.getMethod().getExceptionTypes());
        this.guidance = fuzzGuidance;
        this.skipExceptionSwallow = Boolean.getBoolean("jqf.failOnDeclaredExceptions");
    }

    private List<Integer> getMutationDist(Object[] parent, Object[] child) {
        // should be the same length as the # of generators are the same
        assert parent != null && child != null && parent.length == child.length;
        if (this.guidance instanceof AFLGuidance) {
            // cannot run testWithGenerator methods with AFL
            return IntStream.range(0, parent.length)
                    .map(i ->
                    {
                        assert parent[i] instanceof InputStreamAFL && child[i] instanceof InputStreamAFL;
                        return getLevenshteinDistFromInputstream((InputStreamAFL) parent[i], (InputStreamAFL) child[i]);
                    })
                    .boxed()
                    .collect(Collectors.toList());
        }
        return IntStream.range(0, parent.length)
                .map(i -> getLevenshteinDist(parent[i].toString(), child[i].toString()))
                .boxed()
                .collect(Collectors.toList());
    }

    private int getLevenshteinDistFromInputstream(InputStreamAFL in1, InputStreamAFL in2) {
        List<Integer> s1 = in1.getAllBytes();
        List<Integer> s2 = in2.getAllBytes();
        if (s1.equals(s2)) {
            return 0;
        }
        int n = s2.size();
        int[] v0 = new int[n + 1];
        int[] v1 = new int[n + 1];
        for (int i = 0; i < s2.size() + 1; i++) {
            v0[i] = i;
        }
        for (int i = 0; i < s1.size(); i++) {
            v1[0] = i + 1;
            for (int j = 0; j < s2.size(); j++) {
                int deletionCost = v0[j + 1] + 1;
                int insertionCost = v1[j] + 1;
                int substitutionCost = 0;
                if (s1.get(i) == s2.get(j)) {
                    substitutionCost = v0[j];
                } else {
                    substitutionCost = v0[j] + 1;
                }
                int min = deletionCost < insertionCost ? deletionCost : insertionCost;
                v1[j + 1] = min < substitutionCost ? min : substitutionCost;
            }
            // swap
            int[] tmp = v0;
            v0 = v1;
            v1 = tmp;
        }
        return v0[n];
    }

    // optimized using two matrix rows
    private int getLevenshteinDist(String s1, String s2) {
        if (s1.equals(s2)) {
            return 0;
        }
        int n = s2.length();
        int[] v0 = new int[n + 1];
        int[] v1 = new int[n + 1];
        for (int i = 0; i < s2.length() + 1; i++) {
            v0[i] = i;
        }
        for (int i = 0; i < s1.length(); i++) {
            v1[0] = i + 1;
            for (int j = 0; j < s2.length(); j++) {
                int deletionCost = v0[j + 1] + 1;
                int insertionCost = v1[j] + 1;
                int substitutionCost = 0;
                if (s1.charAt(i) == s2.charAt(j)) {
                    substitutionCost = v0[j];
                } else {
                    substitutionCost = v0[j] + 1;
                }
                int min = deletionCost < insertionCost ? deletionCost : insertionCost;
                v1[j + 1] = min < substitutionCost ? min : substitutionCost;
            }
            // swap
            int[] tmp = v0;
            v0 = v1;
            v1 = tmp;
        }
        return v0[n];
    }

    /**
     * Run the test.
     *
     * @throws Throwable if the test fails
     */
    @Override
    public void evaluate() throws Throwable {
        // Construct generators for each parameter
        List<Generator<?>> generators = Arrays.stream(method.getMethod().getParameters())
                .map(this::createParameterTypeContext)
                .map(generatorRepository::produceGenerator)
                .collect(Collectors.toList());

        ExecutorService executor = Executors.newFixedThreadPool(10);

        // Keep fuzzing until no more input or I/O error with guidance
        try {
            // input generated
            final Object[][] args = {null};
            // parent status saved from last run
            final Object[][] parentArgs = {null};
            final IntIntHashMap[] parentCoverage = {null};
            List<Integer> parentIdx = new ArrayList<>();

            // Keep fuzzing as long as guidance wants to
            while (guidance.hasInput()) {
                Result result = INVALID;
                Throwable error = null;

                // Initialize guided fuzzing using a file-backed random number source
                try {
                    try {
                        // Generate input values
                        StreamBackedRandom randomFile = new StreamBackedRandom(guidance.getInput(), Long.BYTES);
                        SourceOfRandomness random = new FastSourceOfRandomness(randomFile);
                        GenerationStatus genStatus = new NonTrackingGenerationStatus(random);
                        args[0] = generators.stream()
                                .map(g -> g.generate(random, genStatus))
                                .toArray();

                        // Let guidance observe the generated input args
                        guidance.observeGeneratedArgs(args[0]);
                    } catch (IllegalStateException e) {
                        if (e.getCause() instanceof EOFException) {
                            // This happens when we reach EOF before reading all the random values.
                            // The only thing we can do is try again
                            continue;
                        } else {
                            throw e;
                        }
                    } catch (AssumptionViolatedException | TimeoutException e) {
                        // Propagate early termination of tests from generator
                        continue;
                    } catch (GuidanceException e) {
                        // Throw the guidance exception outside to stop fuzzing
                        throw e;
                    } catch (Throwable e) {
                        // Throw the guidance exception outside to stop fuzzing
                        throw new GuidanceException(e);
                    }

                    // Attempt to run the trial
                    guidance.run(testClass, method, args[0]);
                    // If we reached here, then the trial must be a success
                    result = SUCCESS;

                } catch (InstrumentationException e) {
                    // Throw a guidance exception outside to stop fuzzing
                    throw new GuidanceException(e);
                } catch (GuidanceException e) {
                    // Throw the guidance exception outside to stop fuzzing
                    throw e;
                } catch (SyntaxException e) {
                    result = SYNTAXINVALID;
                    error = e;
                } catch (AssumptionViolatedException e) {
                    result = INVALID;
                    error = e;
                } catch (TimeoutException e) {
                    result = TIMEOUT;
                    error = e;
                } catch (Throwable e) {
                    // Check if this exception was expected
                    if (isExceptionExpected(e.getClass())) {
                        result = SUCCESS; // Swallow the error
                    } else {
                        result = FAILURE;
                        error = e;
                        failures.add(e);
                    }
                }

                // Inform guidance about the outcome of this trial
                try {
                    // handle the results
                    guidance.handleResult(result, error, args[0]);
                    IntIntHashMap coverage = guidance.getCoverageMap();

                    // logging
                    Result finalResult = result;
                    Runnable run = new Runnable() {
                        @Override
                        public void run() {
                            int currentParentIdx = -1;
                            StringBuilder parentArgsStr = new StringBuilder();
                            StringBuilder parentCoverageStr = new StringBuilder();
                            StringBuilder covStr = new StringBuilder("c:");

                            if (guidance instanceof ZestGuidance) {
                                ZestGuidance zest = (ZestGuidance) guidance;
                                parentArgs[0] = zest.getCurrentParentInput();
                                parentCoverage[0] = zest.getCurrentParentInputCoverage();
                                currentParentIdx = zest.getCurrentParentInputIdx();

                                if (parentArgs[0][0] instanceof Document) {
                                    parentArgs[0] = Arrays.stream(parentArgs[0]).map(o -> documentToString((Document) o)).toArray();
                                }
                                if (parentIdx.contains(currentParentIdx)) {
                                    parentArgsStr.append("s");
                                    parentCoverageStr.append("s");
                                } else {
                                    parentArgsStr.append(Arrays.toString(parentArgs[0]));
                                    parentCoverageStr.append(parentCoverage[0].toString());
                                }
                            }

                            if (parentIdx.contains(currentParentIdx) && coverage.equals(parentCoverage[0])) {
                                covStr.append("s");
                            } else {
                                covStr.append(coverage);
                            }
                            // handle the special case of Document
                            if (args[0][0] instanceof Document) {
                                args[0] = Arrays.stream(args[0]).map(o -> documentToString((Document) o)).toArray();
                            }
                            // compute the levenshtein distance
                            List<Integer> mutationDistances = getMutationDist(parentArgs[0] == null ? args[0] : parentArgs[0], args[0]);

                            if (currentParentIdx != -1) {
                                String log = String.format("~fz %d~fz %s~fz %s~fz %s~fz %s~fz %s~fz %s",
                                        currentParentIdx,
                                        parentArgsStr,
                                        Arrays.toString(args[0]),
                                        finalResult,
                                        mutationDistances.stream().map(o -> o.toString()).collect(Collectors.joining(", ")),
                                        parentCoverageStr,
                                        covStr);
                                logger.error(log);
                                parentIdx.add(currentParentIdx);
                            } else {
                                String log = String.format("~fz %s~fz %s~fz %s~fz %s",
                                        Arrays.toString(args[0]),
                                        finalResult,
                                        mutationDistances.stream().map(o -> o.toString()).collect(Collectors.joining(", ")),
                                        covStr);
                                logger.error(log);
                            }
                        }
                    };

                    executor.execute(run);

                    // save current status as the parent status
                    parentArgs[0] = args[0];
                    parentCoverage[0] = coverage;

                } catch (GuidanceException e) {
                    throw e; // Propagate
                } catch (Throwable e) {
                    // Anything else thrown from handleResult is an internal error, so wrap
                    throw new GuidanceException(e);
                }
            }
        } catch (GuidanceException e) {
            System.err.println("Fuzzing stopped due to guidance exception: " + e.getMessage());
            throw e;
        }
        executor.shutdown();
        executor.awaitTermination(6, TimeUnit.HOURS);

        if (failures.size() > 0) {
            if (failures.size() == 1) {
                throw failures.get(0);
            } else {
                // Not sure if we should report each failing run,
                // as there may be duplicates
                throw new MultipleFailureException(failures);
            }
        }
    }

    /**
     * Returns whether an exception is expected to be thrown by a trial method
     *
     * @param e the class of an exception that is thrown
     * @return <code>true</code> if e is a subclass of any exception specified
     * in the <code>throws</code> clause of the trial method.
     */
    private boolean isExceptionExpected(Class<? extends Throwable> e) {
        if (skipExceptionSwallow) {
            return false;
        }
        for (Class<?> expectedException : expectedExceptions) {
            if (expectedException.isAssignableFrom(e)) {
                return true;
            }
        }
        return false;
    }

    private ParameterTypeContext createParameterTypeContext(Parameter parameter) {
        return ParameterTypeContext.forParameter(parameter, generics).annotate(parameter);
    }

    // a helper method to read the document
    private static String documentToString(Document document) {
        try {
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            StringWriter stream = new StringWriter();
            transformer.transform(new DOMSource(document), new StreamResult(stream));
            return stream.toString();
        } catch (TransformerException e) {
            throw new RuntimeException(e);
        }
    }
}
