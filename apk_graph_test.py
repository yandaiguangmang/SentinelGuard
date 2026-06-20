from androguard.core.bytecodes.apk import APK
from SentinelGuard.analyzers.apk_graph_extractor import APKGraphExtractor

apk_path = r'G:\testcases\apk\Yahnac.apk'
apk = APK(apk_path)

extractor = APKGraphExtractor()

apk_summary = {
    "package_name": apk.get_package(),
    "file_name": "Yahnac.apk",
}

result = extractor.extract_all(apk, apk_summary)

print(f"是否 fallback: {result.get('fallback', False)}")
print(f"\n=== 图统计 ===")
print(f"CFG 节点数: {len(result['cfg']['nodes'])}")
print(f"CFG 边数: {len(result['cfg']['edges'])}")
print(f"FCG 节点数: {len(result['fcg']['nodes'])}")
print(f"FCG 边数: {len(result['fcg']['edges'])}")
print(f"API 节点数: {len(result['api_graph']['nodes'])}")
print(f"API 边数: {len(result['api_graph']['edges'])}")

print(f"\n=== API 调用统计 ===")
api_counts = result['api_graph']['api_call_counts']
for api, count in list(api_counts.items())[:10]:
    print(f"  {api}: {count}")

print(f"\n=== 综合统计 ===")
for key, value in result['stats'].items():
    print(f"  {key}: {value}")