from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict
from math import log2
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from SentinelGuard.state import GraphNodeFeature, GraphStructure
from .apk_rules import SENSITIVE_API_RULES, match_sensitive_api, sensitive_api_category

try:  # pragma: no cover - optional dependency fallback
    from androguard.core.bytecodes.dvm import DalvikVMFormat
except Exception:  # pragma: no cover - dependency fallback
    try:
        # Newer androguard releases may move dex parsing helpers.
        from androguard.core.dex import DEX as DalvikVMFormat
    except Exception:  # pragma: no cover - dependency fallback
        DalvikVMFormat = None


class APKGraphExtractor:
    """Extract CFG / FCG / API graphs from APK dex data.

    The implementation is intentionally defensive:
    - if androguard is available and the dex payload can be parsed, it extracts
      graph-like structures from DalvikVMFormat objects;
    - if androguard is unavailable or parsing fails, it falls back to a
      heuristic graph synthesized from APK summary metadata.
    """

    SENSITIVE_APIS: Dict[str, Tuple[str, ...]] = SENSITIVE_API_RULES

    def extract_all(self, dex_data: Any, apk_summary: Dict[str, Any]) -> Dict[str, Any]:
        """入口方法，返回包含 cfg、fcg、api_graph、stats 的字典。"""

        vm = self._build_vm(dex_data)
        if vm is None:
            graph_data = self._extract_fallback(dex_data, apk_summary)
            graph_data["stats"] = self._compute_graph_stats(graph_data)
            return graph_data

        cfg = self._extract_cfg(vm)
        fcg = self._extract_fcg(vm)
        api_graph = self._extract_api_graph(vm)
        graph_data = {
            "cfg": cfg,
            "fcg": fcg,
            "api_graph": api_graph,
        }
        graph_data["stats"] = self._compute_graph_stats(graph_data)
        return graph_data

    def _build_vm(self, dex_data: Any) -> Any:
        if DalvikVMFormat is None:
            return None
        
        dex_blobs = self._normalize_dex_blobs(dex_data)
        
        if not dex_blobs:
            return None

        vms: List[Any] = []
        for idx, dex_bytes in enumerate(dex_blobs):
            try:
                vm = DalvikVMFormat(dex_bytes)
                if vm is not None:
                    vms.append(vm)
            except Exception as e:
                continue

        if not vms:
            return None
        return vms[0] if len(vms) == 1 else vms

    def _normalize_dex_blobs(self, dex_data: Any) -> List[bytes]:
        if dex_data is None:
            return []
        
        # 处理 bytes/bytearray
        if isinstance(dex_data, (bytes, bytearray)):
            return [bytes(dex_data)] if dex_data else []
        
        # 处理字符串（文件路径）
        if isinstance(dex_data, str):
            payload = dex_data.encode("utf-8", errors="ignore")
            return [payload] if payload else []
        
        # 处理 APK 对象（关键修复）
        if hasattr(dex_data, 'get_dex'):
            try:
                dex_result = dex_data.get_dex()
                if dex_result is None:
                    return []
                
                # 如果返回的是 bytes（你的情况）
                if isinstance(dex_result, (bytes, bytearray)):
                    return [bytes(dex_result)] if dex_result else []
                
                # 如果返回的是列表
                if isinstance(dex_result, (list, tuple)):
                    chunks: List[bytes] = []
                    for item in dex_result:
                        if isinstance(item, (bytes, bytearray)):
                            blob = bytes(item)
                            if blob:
                                chunks.append(blob)
                        elif hasattr(item, 'get_data'):
                            try:
                                data = item.get_data()
                                if data:
                                    chunks.append(bytes(data))
                            except Exception:
                                pass
                    return chunks
                
                # 如果返回的是迭代器
                if hasattr(dex_result, '__iter__'):
                    chunks = []
                    for item in dex_result:
                        if isinstance(item, (bytes, bytearray)):
                            chunks.append(bytes(item))
                        elif hasattr(item, 'get_data'):
                            try:
                                data = item.get_data()
                                if data:
                                    chunks.append(bytes(data))
                            except Exception:
                                pass
                        # 安全检查：正常 APK 不会超过 10 个 DEX
                        if len(chunks) > 50:
                            print(f"[WARN] DEX 数量异常（>50），截断处理")
                            break
                    return chunks
                    
            except Exception as e:
                print(f"[WARN] APK.get_dex() 调用失败: {e}")
                return []
        
        # 处理 Sequence（列表、元组等）
        if isinstance(dex_data, Sequence) and not isinstance(dex_data, (str, bytes, bytearray)):
            chunks: List[bytes] = []
            for item in dex_data:
                if isinstance(item, (bytes, bytearray)):
                    blob = bytes(item)
                    if blob:
                        chunks.append(blob)
                elif isinstance(item, str):
                    blob = item.encode("utf-8", errors="ignore")
                    if blob:
                        chunks.append(blob)
            return chunks
        
        return []

    def _extract_cfg(self, vm: Any) -> Dict[str, Any]:
        """提取控制流图，从指令流中构建基本块"""
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        methods = self._iter_methods(vm)
        method_index = 0
        
        for method in methods:
            instructions = self._method_instructions(method)
            if not instructions:
                continue

            method_name = self._method_signature(method)
            node_id = f"m{method_index}"
            
            # 统计方法的指令特征
            feature = GraphNodeFeature()
            for inst in instructions:
                self._update_features(self._instruction_name(inst), feature)

            # 添加方法节点
            nodes.append({
                "id": node_id,
                "name": method_name,
                "feature": feature.to_dict(),
                "instruction_count": len(instructions),
            })

            # 从指令流构建基本块
            blocks = self._build_basic_blocks(instructions)
            
            if blocks:
                # 添加基本块节点（作为方法节点的子节点）
                previous_block_id: Optional[str] = None
                for block_index, block_instructions in enumerate(blocks):
                    if not block_instructions:
                        continue
                        
                    block_id = f"{node_id}_b{block_index}"
                    block_feature = GraphNodeFeature()
                    for inst in block_instructions:
                        self._update_features(self._instruction_name(inst), block_feature)
                    
                    nodes.append({
                        "id": block_id,
                        "name": f"{method_name}#block{block_index}",
                        "feature": block_feature.to_dict(),
                        "instruction_count": len(block_instructions),
                        "parent": node_id,
                    })
                    
                    # 添加顺序边
                    if previous_block_id is not None:
                        edges.append({
                            "source": previous_block_id, 
                            "target": block_id, 
                            "kind": "cfg"
                        })
                    previous_block_id = block_id
                
                # 添加控制流边（分支跳转）
                for block_index, block_instructions in enumerate(blocks):
                    if not block_instructions:
                        continue
                        
                    # 检查最后一条指令是否是分支指令
                    last_inst = block_instructions[-1] if block_instructions else None
                    if last_inst:
                        inst_name = self._instruction_name(last_inst).lower()
                        # 如果是无条件跳转或条件跳转，尝试找到目标
                        if inst_name.startswith(('goto', 'if-', 'packed-switch', 'sparse-switch')):
                            # 获取跳转目标
                            target_label = self._get_jump_target(last_inst)
                            if target_label:
                                # 在 blocks 中查找目标块
                                target_block_index = self._find_block_by_label(blocks, target_label)
                                if target_block_index is not None and target_block_index != block_index:
                                    source_id = f"{node_id}_b{block_index}"
                                    target_id = f"{node_id}_b{target_block_index}"
                                    edges.append({
                                        "source": source_id,
                                        "target": target_id,
                                        "kind": "cfg_branch"
                                    })
            
            method_index += 1

        return {"nodes": nodes, "edges": edges}
    
    def _build_basic_blocks(self, instructions: List[Any]) -> List[List[Any]]:
        """从指令流构建基本块"""
        if not instructions:
            return []
        
        blocks: List[List[Any]] = []
        current_block: List[Any] = []
        
        # 分支指令列表
        branch_instructions = {
            'goto', 'if-eq', 'if-ne', 'if-lt', 'if-ge', 'if-gt', 'if-le',
            'if-eqz', 'if-nez', 'if-ltz', 'if-gez', 'if-gtz', 'if-lez',
            'packed-switch', 'sparse-switch'
        }
        
        # 返回指令（基本块结束）
        return_instructions = {'return-void', 'return', 'return-wide', 'return-object'}
        
        for inst in instructions:
            inst_name = self._instruction_name(inst).lower()
            
            # 添加指令到当前块
            current_block.append(inst)
            
            # 检查是否是块结束指令
            is_branch = any(inst_name.startswith(branch) for branch in branch_instructions)
            is_return = any(inst_name.startswith(ret) for ret in return_instructions)
            
            if is_branch or is_return:
                # 结束当前块
                blocks.append(current_block)
                current_block = []
        
        # 添加最后一个块（如果有剩余指令）
        if current_block:
            blocks.append(current_block)
        
        return blocks

    def _get_jump_target(self, inst: Any) -> Optional[str]:
        """获取跳转指令的目标标签"""
        try:
            output = self._instruction_output(inst) or ""
            # 提取标签（通常格式为 :label_xxx 或 +xx）
            import re
            # 匹配 :label_xxx 格式
            match = re.search(r':([a-zA-Z_][a-zA-Z0-9_]*)', output)
            if match:
                return match.group(1)
            # 匹配数字偏移
            match = re.search(r'([+-]\d+)', output)
            if match:
                return match.group(1)
        except Exception:
            pass
        return None

    def _find_block_by_label(self, blocks: List[List[Any]], label: str) -> Optional[int]:
        """根据标签查找基本块索引"""
        for idx, block in enumerate(blocks):
            for inst in block:
                inst_name = self._instruction_name(inst).lower()
                if inst_name.startswith(':'):
                    # 检查是否是标签指令
                    if label in self._instruction_output(inst):
                        return idx
        return None

    def _update_features(self, inst_name: str, features: GraphNodeFeature) -> None:
        name = (inst_name or "").lower()
        if not name:
            return

        if name.startswith("move"):
            features.move_count += 1
        elif name.startswith("return"):
            features.return_count += 1
        elif name.startswith("monitor"):
            features.monitor_count += 1
        elif name.startswith("instance"):
            features.instance_count += 1
        elif name.startswith("array"):
            features.array_count += 1
        elif name.startswith(("goto", "if-", "packed-switch", "sparse-switch", "throw")):
            features.jump_count += 1
        elif name.startswith(("cmp", "cmpl", "cmpg")) or "compare" in name:
            features.compare_count += 1
        elif name.startswith(("iget", "iput", "sget", "sput")):
            features.field_count += 1
        elif name.startswith(("invoke", "call")):
            features.call_count += 1
        elif name.startswith(("cast", "check-cast", "instance-of", "new-instance", "new-array")):
            features.transform_count += 1
        elif name.startswith(("add", "sub", "mul", "div", "rem", "neg", "shl", "shr", "and", "or", "xor")):
            features.arithmetic_count += 1
        elif name.startswith(("and", "or", "xor", "not")):
            features.logic_count += 1

        if "string" in name or "const-string" in name:
            features.string_const_count += 1
        if "const" in name and any(token in name for token in ("4", "16", "high16", "wide", "number", "float", "double")):
            features.number_const_count += 1

    def _extract_fcg(self, vm: Any) -> Dict[str, Any]:
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        seen_nodes: Dict[str, int] = {}

        for method in self._iter_methods(vm):
            instructions = self._method_instructions(method)
            if not instructions:
                continue
                
            caller = self._method_signature(method)
            if caller not in seen_nodes:
                seen_nodes[caller] = len(nodes)
                nodes.append({"id": caller, "name": caller})

            for callee in self._method_called_methods(method):
                if callee not in seen_nodes:
                    seen_nodes[callee] = len(nodes)
                    nodes.append({"id": callee, "name": callee})
                edges.append({"source": caller, "target": callee, "kind": "fcg"})

        return {"nodes": nodes, "edges": edges}

    def _extract_api_graph(self, vm: Any) -> Dict[str, Any]:
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        api_call_counts: Counter[str] = Counter()
        api_nodes: Dict[str, str] = {}

        for method in self._iter_methods(vm):
            instructions = self._method_instructions(method)
            if not instructions:
                continue
                
            caller = self._method_signature(method)
            for inst in instructions:
                inst_name = self._instruction_name(inst)
                called_api = self._match_sensitive_api(inst)
                if not called_api:
                    continue
                api_call_counts[called_api] += 1
                if called_api not in api_nodes:
                    api_id = f"api_{len(api_nodes)}"
                    api_nodes[called_api] = api_id
                    category = self._sensitive_api_category(called_api)
                    nodes.append({"id": api_id, "name": called_api, "category": category})
                edges.append({"source": caller, "target": api_nodes[called_api], "kind": "api_call", "instruction": inst_name})

        return {
            "nodes": nodes,
            "edges": edges,
            "api_call_counts": dict(api_call_counts),
        }

    def _extract_fallback(self, dex_data: Any, apk_summary: Dict[str, Any]) -> Dict[str, Any]:
        package_name = str(apk_summary.get("package_name") or "unknown.package")
        file_name = str(apk_summary.get("file_name") or "unknown.apk")
        dex_count = self._estimate_dex_count(dex_data, apk_summary)

        cfg_nodes = [{
            "id": "fallback_cfg_root",
            "name": file_name,
            "feature": asdict(GraphNodeFeature()),
            "instruction_count": 0,
            "fallback": True,
        }]
        fcg_nodes = [
            {"id": "fallback_entry", "name": package_name},
            {"id": "fallback_apk", "name": file_name},
        ]
        fcg_edges = [{"source": "fallback_entry", "target": "fallback_apk", "kind": "fallback"}]

        api_graph_nodes: List[Dict[str, Any]] = []
        api_graph_edges: List[Dict[str, Any]] = []
        api_call_counts = {category: 0 for category in self.SENSITIVE_APIS}

        return {
            "cfg": {"nodes": cfg_nodes, "edges": []},
            "fcg": {"nodes": fcg_nodes, "edges": fcg_edges},
            "api_graph": {"nodes": api_graph_nodes, "edges": api_graph_edges, "api_call_counts": api_call_counts},
            "fallback": True,
            "fallback_reason": "androguard_unavailable_or_parse_failed",
            "source": {
                "file_name": file_name,
                "package_name": package_name,
                "dex_count": dex_count,
            },
        }

    def _compute_graph_stats(self, graph_data: Dict[str, Any]) -> Dict[str, Any]:
        cfg_nodes = self._graph_nodes(graph_data.get("cfg"))
        cfg_edges = self._graph_edges(graph_data.get("cfg"))
        fcg_nodes = self._graph_nodes(graph_data.get("fcg"))
        fcg_edges = self._graph_edges(graph_data.get("fcg"))
        api_nodes = self._graph_nodes(graph_data.get("api_graph"))
        api_edges = self._graph_edges(graph_data.get("api_graph"))

        total_nodes = len(cfg_nodes) + len(fcg_nodes) + len(api_nodes)
        total_edges = len(cfg_edges) + len(fcg_edges) + len(api_edges)
        density = self._density(total_nodes, total_edges)
        avg_degree = (2 * total_edges / total_nodes) if total_nodes else 0.0

        api_call_counts = graph_data.get("api_graph", {}).get("api_call_counts", {}) or {}
        most_frequent_api = None
        if api_call_counts:
            most_frequent_api = max(api_call_counts.items(), key=lambda item: item[1])[0]

        return {
            "cfg_node_count": len(cfg_nodes),
            "cfg_edge_count": len(cfg_edges),
            "fcg_node_count": len(fcg_nodes),
            "fcg_edge_count": len(fcg_edges),
            "api_graph_node_count": len(api_nodes),
            "api_graph_edge_count": len(api_edges),
            "total_node_count": total_nodes,
            "total_edge_count": total_edges,
            "density": density,
            "average_degree": avg_degree,
            "api_call_type_count": len(api_call_counts),
            "top_api_call": most_frequent_api,
            "has_fallback": bool(graph_data.get("fallback")),
        }

    def _iter_methods(self, vm: Any) -> List[Any]:
        methods: List[Any] = []
        for unit in self._iter_vm_units(vm):
            for attr in ("get_methods", "get_all_methods", "methods"):
                candidate = getattr(unit, attr, None)
                if callable(candidate):
                    try:
                        unit_methods = list(candidate())
                        if unit_methods:
                            methods.extend(unit_methods)
                            break
                    except Exception:
                        continue
                elif candidate:
                    try:
                        unit_methods = list(candidate)
                        if unit_methods:
                            methods.extend(unit_methods)
                            break
                    except Exception:
                        continue
        if not methods:
            return []

        unique_methods: List[Any] = []
        seen_signatures: set[str] = set()
        for method in methods:
            signature = self._method_signature(method)
            if signature in seen_signatures:
                continue
            seen_signatures.add(signature)
            unique_methods.append(method)
        return unique_methods

    def _iter_vm_units(self, vm: Any) -> List[Any]:
        if vm is None:
            return []
        if isinstance(vm, Sequence) and not isinstance(vm, (str, bytes, bytearray)):
            return [unit for unit in vm if unit is not None]
        return [vm]

    def _method_signature(self, method: Any) -> str:
        for attr in ("get_class_name", "class_name"):
            class_name = self._call_or_value(method, attr)
            if class_name:
                break
        else:
            class_name = "<unknown>"

        for attr in ("get_name", "name"):
            method_name = self._call_or_value(method, attr)
            if method_name:
                break
        else:
            method_name = "<unknown>"

        descriptor = self._call_or_value(method, "get_descriptor") or self._call_or_value(method, "descriptor") or ""
        return f"{class_name}->{method_name}{descriptor}"

    def _method_instructions(self, method: Any) -> List[Any]:
        """提取方法的指令列表，兼容 Androguard 3.3.5"""
        try:
            code = self._call_or_value(method, "get_code")
            if code is None:
                code = getattr(method, 'code', None)
            if code is None:
                return []
            
            # 关键修复：先获取 bc，再获取 instructions
            bc = self._call_or_value(code, "get_bc")
            if bc is None:
                bc = getattr(code, 'bc', None)
            if bc is None:
                return []
            
            # 从 bc 获取指令
            instructions = self._call_or_value(bc, "get_instructions")
            if instructions is None:
                instructions = getattr(bc, 'instructions', None)
            if instructions is None:
                return []
            
            # 转换为列表
            if hasattr(instructions, '__iter__') and not isinstance(instructions, (list, tuple)):
                return list(instructions)
            elif isinstance(instructions, (list, tuple)):
                return list(instructions)
            
            return []
        except Exception as e:
            # 调试时取消注释
            # print(f"[DEBUG] _method_instructions 异常: {type(e).__name__}: {e}")
            return []

    def _method_basic_blocks(self, method: Any) -> List[Any]:
        """提取方法的基本块，兼容 Androguard 3.3.5"""
        try:
            # 方法1: 从 method 直接获取
            for attr in ("basic_blocks", "get_basic_blocks"):
                value = getattr(method, attr, None)
                if value is not None:
                    try:
                        if callable(value):
                            result = value()
                            if result:
                                if hasattr(result, '__iter__') and not isinstance(result, (list, tuple)):
                                    return list(result)
                                return list(result)
                        elif hasattr(value, '__iter__'):
                            return list(value)
                    except Exception:
                        continue
            
            # 方法2: 从 code 获取
            code = self._call_or_value(method, "get_code")
            if code:
                for attr in ("basic_blocks", "get_basic_blocks"):
                    value = getattr(code, attr, None)
                    if value is not None:
                        try:
                            if callable(value):
                                result = value()
                                if result:
                                    if hasattr(result, '__iter__') and not isinstance(result, (list, tuple)):
                                        return list(result)
                                    return list(result)
                            elif hasattr(value, '__iter__'):
                                return list(value)
                        except Exception:
                            continue
            
            return []
        except Exception:
            return []

    def _block_instructions(self, block: Any) -> List[Any]:
        for attr in ("get_instructions", "instructions"):
            value = getattr(block, attr, None)
            if callable(value):
                try:
                    result = list(value())
                    if result:
                        return result
                except Exception:
                    continue
            elif value:
                try:
                    result = list(value)
                    if result:
                        return result
                except Exception:
                    continue
        return []

    def _method_called_methods(self, method: Any) -> List[str]:
        called: List[str] = []
        for inst in self._method_instructions(method):
            target = self._call_target_signature(inst)
            if target and target not in called:
                called.append(target)
        return called

    def _call_target_signature(self, inst: Any) -> str:
        # Try the most common androguard instruction helpers first.
        for attr in ("get_name", "get_output"):
            if hasattr(inst, attr):
                try:
                    value = getattr(inst, attr)()
                    if value:
                        text = str(value)
                        if any(token in text for token in ("invoke-", "call")):
                            return text.strip()
                except Exception:
                    continue

        # Fall back to parsing textual representation.
        text = self._instruction_name(inst)
        if "invoke-" in text or "call" in text:
            return text
        output = self._instruction_output(inst)
        if "->" in output:
            return output.split()[0].strip()
        return ""

    def _match_sensitive_api(self, inst: Any) -> str:
        output = self._instruction_output(inst) or ""
        name = self._instruction_name(inst) or ""
        combined = f"{output} {name}".lower()

        # 更宽松的匹配：同时检查完整签名与短名称，降低对原始输出格式的依赖
        for _category, signatures in SENSITIVE_API_RULES.items():
            for signature in signatures:
                short_name = signature.split(";->")[-1] if ";->" in signature else signature
                short_name = short_name.split("(")[0]
                if signature.lower() in combined or short_name.lower() in combined:
                    return signature
        return ""

    def _sensitive_api_category(self, signature: str) -> str:
        return sensitive_api_category(signature)

    def _instruction_name(self, inst: Any) -> str:
        name = self._call_or_value(inst, "get_name") or self._call_or_value(inst, "name")
        return str(name or "")

    def _instruction_output(self, inst: Any) -> str:
        output = self._call_or_value(inst, "get_output")
        if output:
            return str(output)
        return str(inst or "")

    def _call_or_value(self, obj: Any, attr: str) -> Any:
        """安全获取对象的属性或方法返回值"""
        if obj is None:
            return None
        try:
            value = getattr(obj, attr, None)
            if value is None:
                return None
            if callable(value):
                try:
                    return value()
                except Exception:
                    return None
            return value
        except Exception:
            return None

    def _graph_nodes(self, graph_part: Any) -> List[Any]:
        if isinstance(graph_part, dict):
            return list(graph_part.get("nodes", []))
        return []

    def _graph_edges(self, graph_part: Any) -> List[Any]:
        if isinstance(graph_part, dict):
            return list(graph_part.get("edges", []))
        return []

    def _density(self, nodes: int, edges: int) -> float:
        if nodes <= 1:
            return 0.0
        return min(1.0, edges / (nodes * (nodes - 1)))

    def _estimate_dex_count(self, dex_data: Any, apk_summary: Dict[str, Any]) -> int:
        if isinstance(dex_data, (bytes, bytearray)):
            return 1
        if isinstance(dex_data, Sequence) and not isinstance(dex_data, (str, bytes, bytearray)):
            count = 0
            for item in dex_data:
                if isinstance(item, (bytes, bytearray)) and item:
                    count += 1
            return count
        return int(apk_summary.get("dex_file_count") or apk_summary.get("dex_count") or 0)


__all__ = ["APKGraphExtractor"]