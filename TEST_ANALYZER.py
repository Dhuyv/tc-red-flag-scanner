from analyzer import ClauseAnalyzer
import json

analyzer = ClauseAnalyzer()
with open('sample_policies.json', 'r', encoding='utf-8') as f:
    samples = json.load(f)['samples']

print("--- TESTING CLAUSE ANALYZER ---")
for sample in samples:
    res = analyzer.scan(sample['content'], sample['title'])
    print(f"[{res['risk_level']}] {sample['title']}")
    print(f" Score: {res['risk_score']}/100")
    print(f" Clauses: {res['clauses_analyzed']}, Red Flags: {res['red_flags']}")
    print(f" Severity: High={res['severity_counts']['HIGH']}, Med={res['severity_counts']['MEDIUM']}, Low={res['severity_counts']['LOW']}")
    print(f" Top categories: {[c['category_name'] for c in res['categories'][:3]]}")
    print()

print("ALL SAMPLES TESTED SUCCESSFULLY!")
