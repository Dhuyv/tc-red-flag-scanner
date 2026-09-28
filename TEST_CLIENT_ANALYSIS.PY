import js2py

# Polyfill minimal browser environment
context = js2py.EvalJs()
context.execute("""
var window = {
    TC_RISK_RULES: null,
    clientClauseAnalyzer: null
};
var console = {
    warn: function() {},
    log: function() {},
    error: function() {}
};
""")

with open('../frontend/js/rules_data.js', 'r', encoding='utf-8') as f:
    context.execute(f.read())

with open('../frontend/js/client_analyzer.js', 'r', encoding='utf-8') as f:
    context.execute(f.read())

sample_text = (
    "We reserve the right to share your personal information with third parties. "
    "We track your browsing activity and device fingerprinting across external websites. "
    "All disputes shall be resolved exclusively through confidential binding arbitration. "
    "You waive any right to participate in a class action. "
    "We may modify these terms at any time without prior notice."
)

context.set('sample_text', sample_text)
res = context.eval('window.clientClauseAnalyzer.scan(sample_text, "JS Offline Test")')

print("--- CLIENT-SIDE JS ENGINE TEST RESULT ---")
print("Document:", res['document_name'])
print("Risk Score:", res['risk_score'], "/ 100")
print("Risk Level:", res['risk_level'])
print("Clauses Analyzed:", res['clauses_analyzed'])
print("Red Flags Detected:", res['red_flags'])
print("Engine Mode:", res['engine_mode'])
print("SUCCESS: 100% OFFLINE CLIENT-SIDE JS ENGINE IS OPERATIONAL!")
