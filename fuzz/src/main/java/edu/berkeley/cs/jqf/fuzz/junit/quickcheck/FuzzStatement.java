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
import edu.berkeley.cs.jqf.fuzz.ei.ExecutionIndexingGuidance;
import edu.berkeley.cs.jqf.fuzz.ei.ZestGuidance;
import edu.berkeley.cs.jqf.fuzz.guidance.*;
import edu.berkeley.cs.jqf.fuzz.guidance.TimeoutException;
import edu.berkeley.cs.jqf.fuzz.util.InputStreamAFL;
import edu.berkeley.cs.jqf.fuzz.util.SyntaxException;
import edu.berkeley.cs.jqf.instrument.InstrumentationException;
import org.apache.bcel.classfile.*;
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
import java.util.Date;
import java.util.List;
import java.util.concurrent.*;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.SimpleFormatter;
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

    /**
     * @param parent Notnull
     * @param child  Notnull
     * @return
     */
    private List<Integer> getAFLMutationDist(Object[] parent, Object[] child) {
        // cannot run testWithGenerator methods with AFL
        if (parent == null) {
            return IntStream.range(0, child.length)
                    .map(i -> getLevenshteinDistFromInputStream(Arrays.asList(0),
                            ((InputStreamAFL) child[i]).getAllBytes()))
                    .boxed()
                    .collect(Collectors.toList());
        } else {
            return IntStream.range(0, child.length)
                    .map(i -> getLevenshteinDistFromInputStream(((InputStreamAFL) parent[i]).getAllBytes(),
                            ((InputStreamAFL) child[i]).getAllBytes()))
                    .boxed()
                    .collect(Collectors.toList());
        }
    }

    /**
     * Requires the parent and child to have the same lengths
     *
     * @param parent Notnull
     * @param child  Notnull
     * @return
     */
    private List<Integer> getZestMutationDist(Object[] parent, Object[] child) {
        return IntStream.range(0, child.length)
                .map(i -> getLevenshteinDistFromString(parent[i].toString(), child[i].toString()))
                .boxed()
                .collect(Collectors.toList());
    }

    private int getLevenshteinDistFromInputStream(List<Integer> s1, List<Integer> s2) {
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
    private int getLevenshteinDistFromString(String s1, String s2) {
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

    private void evaluateZest() throws Throwable {
        // log4j logger
        Logger logger = LogManager.getLogger(FuzzStatement.class);
        int nThreads = Runtime.getRuntime().availableProcessors();
        BlockingQueue<Runnable> workQueue = new ArrayBlockingQueue<>(100);
        ExecutorService executor = new ThreadPoolExecutor(nThreads, nThreads, 0L, TimeUnit.MILLISECONDS, workQueue, new RejectedExecutionHandler() {
            @Override
            public void rejectedExecution(Runnable r, ThreadPoolExecutor executor) {
                try {
                    executor.getQueue().put(r);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
                // check afterwards and throw if pool shutdown
                if (executor.isShutdown()) {
                    throw new RejectedExecutionException();
                }
            }
        });
        ZestGuidance zest = (ZestGuidance) guidance;

        // Construct generators for each parameter
        List<Generator<?>> generators = Arrays.stream(method.getMethod().getParameters())
                .map(this::createParameterTypeContext)
                .map(generatorRepository::produceGenerator)
                .collect(Collectors.toList());

        // Keep fuzzing until no more input or I/O error with guidance
        try {
            // input generated
            final Object[][] args = {null};
            List<Integer> prevParents = new ArrayList<>();

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
                    args[0] = convertInputToString(args[0]);
                    guidance.handleResult(result, error, args[0]);

                    // logging starts
                    // Variable 'result' is accessed from within inner class, needs to be final or effectively final
                    String resultStr = result.toString();
                    Runnable run = new Runnable() {
                        @Override
                        public void run() {
                            // log data
                            StringBuilder parentArgsStr = new StringBuilder();
                            StringBuilder parentCoverageStr = new StringBuilder();
                            StringBuilder covStr = new StringBuilder();

                            Object[] parentArgs = zest.getCurrentParentInput();
                            IntIntHashMap coverage = guidance.getCoverageMap();
                            IntIntHashMap parentCoverage = zest.getCurrentParentInputCoverage();
                            int parentIdx = zest.getCurrentParentInputIdx();

                            // string representations of inputs
                            if (parentArgs == null) {
                                parentArgs = new String[args[0].length];
                                Arrays.fill(parentArgs, "");
                            } else {
                                parentArgs = convertInputToString(parentArgs);
                            }
                            // compute the levenshtein distance
                            List<Integer> mutationDistances = getZestMutationDist(parentArgs, args[0]);

                            // check redundant logs
                            if (prevParents.contains(parentIdx)) {
                                if (coverage.equals(parentCoverage)) {
                                    covStr.append("s");
                                } else {
                                    covStr.append(coverage);
                                }
                                parentArgsStr.append("s");
                                parentCoverageStr.append("s");
                            } else {
                                covStr.append(coverage);
                                parentArgsStr.append(Arrays.toString(parentArgs));
                                parentCoverageStr.append(parentCoverage);
                            }

                            String log = String.format("~fz %d~fz %s~fz %s~fz %s~fz %s~fz %s~fz %s~fz",
                                    parentIdx,
                                    parentArgsStr,
                                    Arrays.toString(args[0]),
                                    resultStr,
                                    mutationDistances.stream().map(o -> o.toString()).collect(Collectors.joining(", ")),
                                    parentCoverageStr,
                                    covStr);
                            logger.error(log);
                            // update
                            prevParents.add(parentIdx);
                        }
                    };
                    executor.execute(run);

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

        // shut down the executor
        executor.shutdown();
        executor.awaitTermination(5, TimeUnit.HOURS);

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

    private void evaluateEI() throws Throwable {
        java.util.logging.Logger logger = java.util.logging.Logger.getLogger(FuzzStatement.class.getName());
        FileHandler handler = new FileHandler("mutation.%g.log", 1000000000, 80, true);
        handler.setFormatter(new SimpleFormatter() {
            private static final String format = "%1$tFT%1$tT,%1$tL%2$s%n";

            @Override
            public synchronized String format(LogRecord lr) {
                return String.format(format,
                        new Date(lr.getMillis()),
                        lr.getMessage()
                );
            }
        });
        logger.setUseParentHandlers(false);
        logger.addHandler(handler);

        ExecutionIndexingGuidance ei = (ExecutionIndexingGuidance) guidance;

        // Construct generators for each parameter
        List<Generator<?>> generators = Arrays.stream(method.getMethod().getParameters())
                .map(this::createParameterTypeContext)
                .map(generatorRepository::produceGenerator)
                .collect(Collectors.toList());

        // Keep fuzzing until no more input or I/O error with guidance
        try {
            // input generated
            final Object[][] args = {null};
            List<Integer> prevParents = new ArrayList<>();

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
                    args[0] = convertInputToString(args[0]);
                    guidance.handleResult(result, error, args[0]);

                    // logging starts
                    // Variable 'result' is accessed from within inner class, needs to be final or effectively final
                    String resultStr = result.toString();

                    // log data
                    StringBuilder parentArgsStr = new StringBuilder();
                    StringBuilder parentCoverageStr = new StringBuilder();
                    StringBuilder covStr = new StringBuilder();

                    Object[] parentArgs = ei.getCurrentParentInput();
                    IntIntHashMap coverage = guidance.getCoverageMap();
                    IntIntHashMap parentCoverage = ei.getCurrentParentInputCoverage();
                    int parentIdx = ei.getCurrentParentInputIdx();

                    // string representations of inputs
                    if (parentArgs == null) {
                        parentArgs = new String[args[0].length];
                        Arrays.fill(parentArgs, "");
                    } else {
                        parentArgs = convertInputToString(parentArgs);
                    }
                    // compute the levenshtein distance
                    List<Integer> mutationDistances = getZestMutationDist(parentArgs, args[0]);

                    // check redundant logs
                    if (prevParents.contains(parentIdx)) {
                        if (coverage.equals(parentCoverage)) {
                            covStr.append("s");
                        } else {
                            covStr.append(coverage);
                        }
                        parentCoverageStr.append("s");
                    } else {
                        covStr.append(coverage);
                        parentCoverageStr.append(parentCoverage);
                    }
                    parentArgsStr.append(Arrays.toString(parentArgs));

                    String log = String.format("~fz %d~fz %s~fz %s~fz %s~fz %s~fz %s~fz %s~fz",
                            parentIdx,
                            parentArgsStr,
                            Arrays.toString(args[0]),
                            resultStr,
                            mutationDistances.stream().map(o -> o.toString()).collect(Collectors.joining(", ")),
                            parentCoverageStr,
                            covStr);
                    logger.log(Level.INFO, log);
                    // update
                    prevParents.add(parentIdx);
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

    private void evaluateOthers() throws Throwable {
        // Construct generators for each parameter
        List<Generator<?>> generators = Arrays.stream(method.getMethod().getParameters())
                .map(this::createParameterTypeContext)
                .map(generatorRepository::produceGenerator)
                .collect(Collectors.toList());

        // Keep fuzzing until no more input or I/O error with guidance
        try {
            Object[] args = null;
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
                        args = generators.stream()
                                .map(g -> g.generate(random, genStatus))
                                .toArray();

                        // Let guidance observe the generated input args
                        guidance.observeGeneratedArgs(args);
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
                    guidance.run(testClass, method, args);

                    // If we reached here, then the trial must be a success
                    result = SUCCESS;
                } catch (InstrumentationException e) {
                    // Throw a guidance exception outside to stop fuzzing
                    throw new GuidanceException(e);
                } catch (GuidanceException e) {
                    // Throw the guidance exception outside to stop fuzzing
                    throw e;
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
                    guidance.handleResult(result, error, args);
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
     * Run the test.
     *
     * @throws Throwable if the test fails
     */
    @Override
    public void evaluate() throws Throwable {
        if (guidance.getClass() == ZestGuidance.class) {
            evaluateZest();
        } else if (guidance.getClass() == ExecutionIndexingGuidance.class) {
            evaluateEI();
        } else {
            evaluateOthers();
        }
    }

    /**
     * @param args Notnull
     */
    private Object[] convertInputToString(Object[] args) {
        if (args[0] instanceof Document) {
            return Arrays.stream(args).map(o -> documentToString((Document) o)).toArray();
        } else if (args[0] instanceof JavaClass) {
            return Arrays.stream(args).map(o -> javaClassToString((JavaClass) o)).toArray();
        }
        return args;
    }

    private String javaClassToString(JavaClass object) {
        String access = Utility.accessToString(object.getAccessFlags(), true);
        access = access.isEmpty() ? "" : access + " ";
        StringBuilder buf = new StringBuilder(128);
        buf.append(access).append(Utility.classOrInterface(object.getAccessFlags())).append(" ").append(object.getClassName()).append(" extends ").append(Utility.compactClassName(object.getSuperclassName(), false)).append(',');
        String[] interfaceNames = object.getInterfaceNames();
        int size = interfaceNames.length;
        if (size > 0) {
            buf.append(';');
            for (int i = 0; i < size; ++i) {
                buf.append(interfaceNames[i]);
                if (i < size - 1) {
                    buf.append(", ");
                }
            }
            buf.append(';');
        }
        buf.append(object.getFileName()).append(';');
        buf.append(object.getSourceFileName()).append(';');
        buf.append(object.getMajor()).append(".").append(object.getMinor()).append(';');
        buf.append(object.getAccessFlags()).append(';');
        buf.append(object.getConstantPool().getLength()).append(";");
        buf.append(object.isSuper()).append(";");

        int var6;
        Attribute[] attributes = object.getAttributes();
        if (attributes.length > 0) {
            Attribute[] var9 = attributes;
            int var5 = var9.length;
            for (var6 = 0; var6 < var5; ++var6) {
                Attribute attribute = var9[var6];
                buf.append(attribute + " ");
            }
        }

        AnnotationEntry[] annotations = object.getAnnotationEntries();
        int var14;
        if (annotations != null && annotations.length > 0) {
            buf.append(";");
            AnnotationEntry[] var11 = annotations;
            var6 = annotations.length;
            for (var14 = 0; var14 < var6; ++var14) {
                AnnotationEntry annotation = var11[var14];
                buf.append(annotation + " ");
            }
        }

        Field[] fields = object.getFields();
        if (fields.length > 0) {
            buf.append(";").append(fields.length);
            Field[] var12 = fields;
            var6 = var12.length;

            for (var14 = 0; var14 < var6; ++var14) {
                Field field = var12[var14];
                buf.append(field).append(',');
            }
        }

        Method[] methods = object.getMethods();
        if (methods.length > 0) {
            buf.append(";").append(methods.length).append(",");
            Method[] var13 = methods;
            var6 = var13.length;

            for (var14 = 0; var14 < var6; ++var14) {
                Method method = var13[var14];
                buf.append(method).append(',');
            }
        }
        return buf.toString();
    }

    private String javaClassToStringOriginal(JavaClass object) {
        String access = Utility.accessToString(object.getAccessFlags(), true);
        access = access.isEmpty() ? "" : access + " ";
        StringBuilder buf = new StringBuilder(128);
        buf.append(access).append(Utility.classOrInterface(object.getAccessFlags())).append(" ").append(object.getClassName()).append(" extends ").append(Utility.compactClassName(object.getSuperclassName(), false)).append('\n');
        String[] interfaceNames = object.getInterfaceNames();
        int size = interfaceNames.length;
        if (size > 0) {
            buf.append("implements\t\t");

            for (int i = 0; i < size; ++i) {
                buf.append(interfaceNames[i]);
                if (i < size - 1) {
                    buf.append(", ");
                }
            }
            buf.append('\n');
        }
        buf.append("filename\t\t").append(object.getFileName()).append('\n');
        buf.append("compiled from\t\t").append(object.getSourceFileName()).append('\n');
        buf.append("compiler version\t").append(object.getMajor()).append(".").append(object.getMinor()).append('\n');
        buf.append("access flags\t\t").append(object.getAccessFlags()).append('\n');
        buf.append("constant pool\t\t").append(object.getConstantPool().getLength()).append(" entries\n");
        buf.append("ACC_SUPER flag\t\t").append(object.isSuper()).append("\n");
        int var6;
        Attribute[] attributes = object.getAttributes();
        if (attributes.length > 0) {
            buf.append("\nAttribute(s):\n");
            Attribute[] var9 = attributes;
            int var5 = var9.length;

            for (var6 = 0; var6 < var5; ++var6) {
                Attribute attribute = var9[var6];
                buf.append(attribute + " ");
            }
        }

        AnnotationEntry[] annotations = object.getAnnotationEntries();
        int var14;
        if (annotations != null && annotations.length > 0) {
            buf.append("\nAnnotation(s):\n");
            AnnotationEntry[] var11 = annotations;
            var6 = annotations.length;

            for (var14 = 0; var14 < var6; ++var14) {
                AnnotationEntry annotation = var11[var14];
                buf.append(annotation + " ");
            }
        }

        Field[] fields = object.getFields();
        if (fields.length > 0) {
            buf.append("\n").append(fields.length).append(" fields:\n");
            Field[] var12 = fields;
            var6 = var12.length;

            for (var14 = 0; var14 < var6; ++var14) {
                Field field = var12[var14];
                buf.append("\t").append(field).append('\n');
            }
        }

        Method[] methods = object.getMethods();
        if (methods.length > 0) {
            buf.append("\n").append(methods.length).append(" methods:\n");
            Method[] var13 = methods;
            var6 = var13.length;

            for (var14 = 0; var14 < var6; ++var14) {
                Method method = var13[var14];
                buf.append("\t").append(method).append('\n');
            }
        }
        return buf.toString();
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
