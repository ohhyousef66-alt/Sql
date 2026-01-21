/**
 * Example: Using the SQL Injection Scanning Pipeline
 * 
 * This example demonstrates how to use the new professional
 * staged pipeline for SQL injection detection and enumeration.
 */

import { PipelineController, SafetyControlsManager } from './index';

/**
 * Example 1: Basic Vulnerability Detection (No Enumeration)
 */
async function example1_basicDetection() {
  console.log('\n=== Example 1: Basic Vulnerability Detection ===\n');

  const pipeline = new PipelineController({
    scanId: 'demo-scan-001',
    targetUrl: 'https://example.com/products?id=1',
    enableEnumeration: false, // No enumeration
  });

  // Subscribe to events
  pipeline.on('stage_started', (event: any) => {
    console.log(`▶️  Started: ${event.stage}`);
  });

  pipeline.on('stage_completed', (event: any) => {
    console.log(`✅ Completed: ${event.stage}`);
  });

  pipeline.on('gate_blocked', (event: any) => {
    console.warn(`⛔ Confirmation gate blocked!`);
    event.data.decision.reasons.forEach((r: string) => 
      console.warn(`   - ${r}`)
    );
  });

  try {
    const result = await pipeline.execute();
    console.log('\n✨ Scan completed successfully!');
    console.log('Final State:', result);
  } catch (error) {
    console.error('\n❌ Scan failed:', error);
  }
}

/**
 * Example 2: Scan with Enumeration (Requires Consent)
 */
async function example2_withEnumeration() {
  console.log('\n=== Example 2: Scan with Enumeration ===\n');

  // Get legal warnings that MUST be acknowledged
  const warnings = SafetyControlsManager.getLegalWarnings();
  console.log('📋 Legal Warnings to Acknowledge:');
  warnings.forEach((w: string, i: number) => console.log(`   ${i + 1}. ${w}`));
  console.log('');

  // Create pipeline with user consent
  const pipeline = new PipelineController({
    scanId: 'demo-scan-002',
    targetUrl: 'https://authorized-test-site.com/page?id=1',
    enableEnumeration: true,
    userConsent: {
      acknowledgedWarnings: warnings, // ALL warnings required
      metadata: {
        ipAddress: '192.168.1.100',
        userAgent: 'SecurityScanner/1.0',
      },
    },
  });

  // Monitor progress
  const progressInterval = setInterval(() => {
    const progress = pipeline.getRealProgress();
    console.log(`
📊 Progress Update:
   Stage: ${progress.currentStage}
   Phase: ${progress.currentPhase || 'N/A'}
   Completed: ${progress.completedWorkUnits} / ${progress.totalWorkUnits}
   Remaining: ${progress.remainingWorkUnits}
   Activity: ${progress.lastActivity}
    `);
  }, 5000);

  try {
    const result = await pipeline.execute();
    clearInterval(progressInterval);

    console.log('\n✨ Scan with enumeration completed!');
    
    // Get audit trail
    const audit = pipeline.getAuditTrail();
    console.log('\n🔒 Audit Trail:');
    console.log('   Actions logged:', audit.actions.length);
    console.log('   Enumeration enabled:', audit.userConsent.enumerationEnabled);
    console.log('   Legal warnings acknowledged:', audit.userConsent.acknowledgedLegalWarnings);

  } catch (error) {
    clearInterval(progressInterval);
    console.error('\n❌ Scan failed:', error);
  }
}

/**
 * Example 3: Testing Confirmation Gate
 */
async function example3_confirmationGate() {
  console.log('\n=== Example 3: Confirmation Gate ===\n');

  const { 
    ConfirmationGate, 
    ConfidenceLevel, 
    InjectionTechnique 
  } = await import('./index');

  const gate = new ConfirmationGate({
    minimumSignals: 2,
    minimumConfidence: ConfidenceLevel.HIGH,
    requireDifferentTechniques: true,
    requireDifferentEvidenceTypes: true,
  });

  console.log('📝 Adding confirmation signals...\n');

  // Signal 1: UNION-based injection
  gate.addSignal({
    technique: InjectionTechnique.UNION_BASED,
    payload: "' UNION SELECT NULL,NULL,NULL-- -",
    responseTimeMs: 150,
    evidenceType: 'union_data',
    evidence: 'Successfully extracted 3 columns',
    confidence: ConfidenceLevel.HIGH,
    timestamp: new Date(),
  });

  console.log('✅ Added UNION-based signal');

  // Signal 2: Error-based injection
  gate.addSignal({
    technique: InjectionTechnique.ERROR_BASED,
    payload: "' AND EXTRACTVALUE(1,1)-- -",
    responseTimeMs: 120,
    evidenceType: 'error_message',
    evidence: 'XPATH syntax error detected',
    confidence: ConfidenceLevel.HIGH,
    timestamp: new Date(),
  });

  console.log('✅ Added ERROR-based signal');

  // Evaluate gate
  const decision = gate.evaluate();

  console.log('\n🚦 Gate Decision:');
  console.log('   Passed:', decision.passed);
  console.log('   Confidence:', decision.confidence);
  console.log('   Recommendation:', decision.recommendation);
  console.log('\n   Reasons:');
  decision.reasons.forEach((r: string) => console.log(`   - ${r}`));
}

/**
 * Example 4: Database Fingerprinting
 */
async function example4_fingerprinting() {
  console.log('\n=== Example 4: Database Fingerprinting ===\n');

  const { DatabaseFingerprinter } = await import('./index');

  const fingerprinter = new DatabaseFingerprinter();

  // Mock executor function (would actually send SQL queries)
  const mockExecutor = async (payload: string) => {
    console.log(`   Testing: ${payload.substring(0, 50)}...`);
    
    // Simulate MySQL response
    if (payload.includes('VERSION()')) {
      return '8.0.32-MySQL';
    }
    
    return null;
  };

  console.log('🔍 Fingerprinting database...\n');

  const fingerprint = await fingerprinter.fingerprint(mockExecutor);

  console.log('\n📋 Fingerprint Results:');
  console.log('   Type:', fingerprint.type);
  console.log('   Version:', fingerprint.version || 'Unknown');
  console.log('   Confidence:', fingerprint.confidence);
  console.log('   Detection Method:', fingerprint.detectionMethod);
  console.log('\n   Capabilities:');
  console.log('   - UNION Support:', fingerprint.capabilities.supportsUnion);
  console.log('   - Error-based Support:', fingerprint.capabilities.supportsErrorBased);
  console.log('   - Time-based Support:', fingerprint.capabilities.supportsTimeBased);
  console.log('   - Information Schema:', fingerprint.capabilities.supportsInformationSchema);
}

/**
 * Example 5: Adaptive Pacing
 */
async function example5_adaptivePacing() {
  console.log('\n=== Example 5: Adaptive Pacing ===\n');

  const { AdaptivePacer } = await import('./index');

  const pacer = new AdaptivePacer({
    baseDelayMs: 1000,
    minDelayMs: 100,
    maxDelayMs: 10000,
    errorRateThreshold: 0.3,
  });

  console.log('⏱️  Simulating requests with adaptive pacing...\n');

  // Simulate requests
  for (let i = 0; i < 20; i++) {
    await pacer.wait();

    // Simulate response
    const success = Math.random() > 0.2; // 80% success rate
    const latency = 100 + Math.random() * 200;

    pacer.recordResponse(latency, success, undefined, false);

    const metrics = pacer.calculateMetrics();
    console.log(`Request ${i + 1}:`, {
      success,
      latency: Math.round(latency),
      avgLatency: metrics.averageLatencyMs,
      errorRate: metrics.errorRate,
      currentDelay: pacer.getCurrentDelay(),
      shouldThrottle: metrics.shouldThrottle,
    });

    if (metrics.shouldPause) {
      console.log('   ⏸️  System paused due to errors');
      break;
    }
  }
}

/**
 * Example 6: Response Analysis
 */
async function example6_responseAnalysis() {
  console.log('\n=== Example 6: Response Analysis ===\n');

  const { ResponseAnalyzer } = await import('./index');

  const analyzer = new ResponseAnalyzer();

  const response1 = `
    <html>
      <body>
        <h1>Products</h1>
        <p>Session ID: abc123def456</p>
        <p>Generated at: 2026-01-21 18:00:00</p>
        <script src="analytics.js"></script>
        <p>Product list here</p>
      </body>
    </html>
  `;

  const response2 = `
    <html>
      <body>
        <h1>Products</h1>
        <p>Session ID: xyz789ghi012</p>
        <p>Generated at: 2026-01-21 18:05:30</p>
        <script src="analytics.js"></script>
        <p>Product list here</p>
      </body>
    </html>
  `;

  console.log('🔬 Analyzing responses...\n');

  // Normalize first response
  const norm1 = analyzer.normalize(response1);
  console.log('Normalized Response 1:');
  console.log('   Removed:', norm1.removedElements.join(', '));

  // Compare responses
  const comparison = analyzer.compare(response1, response2);
  console.log('\n📊 Comparison Results:');
  console.log('   Similarity:', (comparison.similarity * 100).toFixed(1) + '%');
  console.log('   Are Different:', comparison.isDifferent);
  console.log('   Difference Score:', (comparison.differenceScore * 100).toFixed(1) + '%');
  console.log('   Structural Difference:', comparison.structuralDifference);
  console.log('   Semantic Difference:', comparison.semanticDifference);
  console.log('\n   Details:');
  comparison.details.forEach((d: string) => console.log(`   - ${d}`));
}

/**
 * Run all examples
 */
async function runAllExamples() {
  // Note: These are demonstrations only
  // In real usage, you would run these against authorized targets

  console.log('\n'.repeat(2));
  console.log('═'.repeat(60));
  console.log('  SQL INJECTION SCANNING PIPELINE - EXAMPLES');
  console.log('═'.repeat(60));

  try {
    await example3_confirmationGate();
    await example4_fingerprinting();
    await example5_adaptivePacing();
    await example6_responseAnalysis();

    // Note: Example 1 and 2 require actual target URLs
    // Uncomment when testing against authorized targets:
    // await example1_basicDetection();
    // await example2_withEnumeration();

    console.log('\n'.repeat(2));
    console.log('═'.repeat(60));
    console.log('  ALL EXAMPLES COMPLETED');
    console.log('═'.repeat(60));
    console.log('\n');
  } catch (error) {
    console.error('Error running examples:', error);
  }
}

// Run if executed directly
if (require.main === module) {
  runAllExamples();
}

export {
  example1_basicDetection,
  example2_withEnumeration,
  example3_confirmationGate,
  example4_fingerprinting,
  example5_adaptivePacing,
  example6_responseAnalysis,
};
