from __future__ import annotations

import asyncio
import inspect
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from openai import OpenAI

try:  # pragma: no cover - optional typing/runtime dependency
    import httpx
except Exception:  # pragma: no cover - httpx is pulled in transitively in normal installs
    httpx = None  # type: ignore[assignment]

try:
    from autogen_agentchat.agents import AssistantAgent
    from autogen_core.model_context import UnboundedChatCompletionContext
    from autogen_core.models import AssistantMessage, SystemMessage, UserMessage
    from autogen_ext.models.openai import OpenAIChatCompletionClient
except Exception:  # pragma: no cover - optional dependency
    AssistantAgent = None
    UnboundedChatCompletionContext = None
    AssistantMessage = None
    SystemMessage = None
    UserMessage = None
    OpenAIChatCompletionClient = None


@dataclass
class RoleConversation:
    role: str
    system_message: str
    model_name: str
    api_key: str
    base_url: str = ""
    client: Any = None
    http_client: Any = None
    temperature: float = 0.2
    top_p: float = 0.9
    _assistant_agent: Any = field(default=None, init=False, repr=False)
    _autogen_model_client: Any = field(default=None, init=False, repr=False)
    _openai_client: Any = field(default=None, init=False, repr=False)
    _history: List[Dict[str, str]] = field(default_factory=list, init=False, repr=False)
    _latest_input: str = field(default="", init=False, repr=False)
    _latest_output: str = field(default="", init=False, repr=False)

    def run(self, task: str, system_message: str | None = None, context: Sequence[Dict[str, str]] | None = None) -> Dict[str, Any]:
        return self.invoke(task, system_message=system_message, context=context)

    def invoke(self, task: str, system_message: str | None = None, context: Sequence[Dict[str, str]] | None = None) -> Dict[str, Any]:
        if system_message is not None and system_message != self.system_message:
            self.system_message = system_message
            self._assistant_agent = None
            self._autogen_model_client = None
        if context:
            self._merge_history(context)
        self._latest_input = task
        start = time.perf_counter()
        
        # 重试配置
        max_retries = 3
        retry_delay = 2.0
        
        for attempt in range(max_retries + 1):
            try:
                if not self.api_key and self.client is None:
                    return {"success": False, "error": f"未配置 {self.role} API Key，无法执行模型深度检查。", "elapsed": 0.0, "usage": None}
                
                # 尝试使用 autogen，失败则降级到 OpenAI
                if self._can_use_autogen():
                    try:
                        content, usage = asyncio.run(self._run_autogen(task))
                    except Exception:
                        content, usage = self._run_openai(task)
                else:
                    content, usage = self._run_openai(task)

                elapsed = time.perf_counter() - start
                if not content:
                    return {"success": False, "error": "模型未返回内容", "elapsed": elapsed, "usage": usage}

                self._latest_output = content
                self._history.extend([
                    {"role": "user", "content": task},
                    {"role": "assistant", "content": content},
                ])
                return {"success": True, "content": content, "elapsed": elapsed, "usage": usage}
                
            except Exception as exc:
                elapsed = time.perf_counter() - start
                if attempt < max_retries:
                    time.sleep(retry_delay * (attempt + 1))
                    continue
                return {"success": False, "error": f"模型调用异常(尝试{attempt+1}次): {exc}", "elapsed": elapsed, "usage": None}
        
        return {"success": False, "error": "模型调用失败", "elapsed": time.perf_counter() - start, "usage": None}

    def append_context(self, messages: Sequence[Dict[str, str]]) -> None:
        self._merge_history(messages)

    def reset(self) -> None:
        self._history.clear()
        self._latest_input = ""
        self._latest_output = ""
        if self._assistant_agent is not None and hasattr(self._assistant_agent, "reset"):
            try:
                self._assistant_agent.reset()
            except Exception:
                pass

    @property
    def history(self) -> List[Dict[str, str]]:
        return list(self._history)

    @property
    def latest_input(self) -> str:
        return self._latest_input

    @property
    def latest_output(self) -> str:
        return self._latest_output

    @property
    def http_transport(self) -> Any:
        if self.http_client is not None:
            return self.http_client
        if self.client is not None:
            return getattr(self.client, "http_client", None)
        return None

    def _merge_history(self, messages: Sequence[Dict[str, str]]) -> None:
        for message in messages:
            if not isinstance(message, dict):
                continue
            role = str(message.get("role") or "")
            content = str(message.get("content") or "")
            if not role or not content:
                continue
            self._history.append({"role": role, "content": content})

    def _can_use_autogen(self) -> bool:
        return AssistantAgent is not None and OpenAIChatCompletionClient is not None and UnboundedChatCompletionContext is not None and bool(self.api_key)

    async def _run_autogen(self, task: str) -> tuple[str, Optional[Dict[str, Any]]]:
        client = self._ensure_autogen_model_client()
        agent = self._ensure_assistant_agent(client)
        self._sync_context(agent, task)
        result = await agent.run(task=task)
        content = _extract_text_from_autogen_result(result)
        usage = _extract_usage_from_autogen_result(result)
        return content, usage

    def _ensure_assistant_agent(self, model_client: Any) -> Any:
        if self._assistant_agent is None:
            context = UnboundedChatCompletionContext()
            self._assistant_agent = AssistantAgent(
                name=self.role,
                model_client=model_client,
                system_message=self.system_message,
                model_context=context,
            )
        return self._assistant_agent

    def _ensure_autogen_model_client(self) -> Any:
        if self._autogen_model_client is None:
            client_kwargs: Dict[str, Any] = {"model": self.model_name}
            if self.api_key:
                client_kwargs["api_key"] = self.api_key
            if self.base_url:
                client_kwargs["base_url"] = self.base_url
            http_client = self.http_transport
            if http_client is not None:
                client_kwargs["http_client"] = http_client
            self._autogen_model_client = _build_autogen_model_client(client_kwargs)
        return self._autogen_model_client

    def _sync_context(self, agent: Any, task: str) -> None:
        context = getattr(agent, "model_context", None)
        if context is None:
            return
        try:
            if not self._history:
                context.clear()
                context.add_message(SystemMessage(content=self.system_message))
            else:
                context.clear()
                context.add_message(SystemMessage(content=self.system_message))
                for message in self._history:
                    if message["role"] == "user":
                        context.add_message(UserMessage(content=message["content"], source=self.role))
                    else:
                        context.add_message(AssistantMessage(content=message["content"], source=self.role))
            context.add_message(UserMessage(content=task, source=self.role))
        except Exception:
            pass

    def _ensure_openai_client(self) -> OpenAI:
        if self._openai_client is not None:
            return self._openai_client
        if self.client is not None and hasattr(self.client, "chat") and hasattr(getattr(self.client, "chat"), "completions"):
            self._openai_client = self.client
            return self._openai_client

        client_kwargs: Dict[str, Any] = {"api_key": self.api_key}
        if self.base_url:
            client_kwargs["base_url"] = self.base_url
        http_client = self.http_transport
        if http_client is not None:
            client_kwargs["http_client"] = http_client
        self._openai_client = OpenAI(**client_kwargs)
        return self._openai_client

    def _run_openai(self, task: str) -> tuple[str, Optional[Dict[str, Any]]]:
        client = self._ensure_openai_client()
        messages = [
            {"role": "system", "content": self.system_message},
            *self._history,
            {"role": "user", "content": task},
        ]

        response = None
        last_error: Exception | None = None

        # 先尝试带 response_format 的请求，如果失败则降级
        for request_kwargs in (
            {"response_format": {"type": "json_object"}},
            {},  # 降级：移除 response_format
        ):
            try:
                response = client.chat.completions.create(
                    model=self.model_name,
                    messages=messages,
                    temperature=self.temperature,
                    top_p=self.top_p,
                    timeout=180.0,  # 添加超时
                    **request_kwargs,
                )
                break
            except Exception as exc:
                last_error = exc
                # 如果已经是降级请求，则继续抛出
                if not request_kwargs:
                    raise

        if response is None:
            raise last_error or RuntimeError("模型请求失败")

        content = response.choices[0].message.content if response.choices else ""
        usage = _extract_usage_from_openai_response(response)
        return content or "", usage


@dataclass
class MultiAgentOrchestrator:
    agents: Dict[str, RoleConversation]
    role_order: List[str]

    def run_round(self, role: str, task: str, system_message: str | None = None, context: Sequence[Dict[str, str]] | None = None) -> Dict[str, Any]:
        return self.agents[role].run(task, system_message=system_message, context=context)

    def broadcast(self, messages: Sequence[Dict[str, str]], exclude: Sequence[str] | None = None) -> None:
        excluded = set(exclude or [])
        for role, agent in self.agents.items():
            if role not in excluded:
                agent.append_context(messages)

    def reset(self) -> None:
        for agent in self.agents.values():
            agent.reset()


def build_role_conversation(
    *,
    role: str,
    system_message: str,
    model_name: str,
    api_key: str,
    base_url: str = "",
    client: Any = None,
    http_client: Any = None,
    temperature: float = 0.2,
    top_p: float = 0.9,
) -> RoleConversation:
    return RoleConversation(
        role=role,
        system_message=system_message,
        model_name=model_name,
        api_key=api_key,
        base_url=base_url,
        client=client,
        http_client=http_client,
        temperature=temperature,
        top_p=top_p,
    )


def build_multi_agent_orchestrator(agents: Dict[str, RoleConversation], role_order: Sequence[str]) -> MultiAgentOrchestrator:
    return MultiAgentOrchestrator(agents=agents, role_order=list(role_order))


def build_role_agent(
    *,
    role: str,
    system_message: str,
    model_name: str,
    api_key: str,
    base_url: str = "",
    client: Any = None,
    http_client: Any = None,
    temperature: float = 0.2,
    top_p: float = 0.9,
) -> RoleConversation:
    return build_role_conversation(
        role=role,
        system_message=system_message,
        model_name=model_name,
        api_key=api_key,
        base_url=base_url,
        client=client,
        http_client=http_client,
        temperature=temperature,
        top_p=top_p,
    )


def run_role_model_completion(
    *,
    role: str,
    system_message: str,
    task: str,
    model_name: str,
    api_key: str,
    base_url: str = "",
    http_client: Any = None,
    temperature: float = 0.2,
    top_p: float = 0.9,
) -> Dict[str, Any]:
    agent = build_role_conversation(
        role=role,
        system_message=system_message,
        model_name=model_name,
        api_key=api_key,
        base_url=base_url,
        http_client=http_client,
        temperature=temperature,
        top_p=top_p,
    )
    return agent.invoke(task)


def _build_autogen_model_client(client_kwargs: Dict[str, Any]):
    last_error: Exception | None = None
    attempts = [
        dict(client_kwargs),
        {k: v for k, v in client_kwargs.items() if k != "http_client"},
        {k: v for k, v in client_kwargs.items() if k not in {"http_client", "base_url"}},
        {k: v for k, v in client_kwargs.items() if k not in {"http_client", "base_url", "api_key"}},
    ]
    for kwargs in attempts:
        try:
            return OpenAIChatCompletionClient(**kwargs)
        except TypeError as exc:
            last_error = exc
            continue
    raise last_error or TypeError("Unable to construct OpenAIChatCompletionClient")


def _extract_text_from_autogen_result(result: Any) -> str:
    for candidate in reversed(list(_iter_message_like_objects(result))):
        content = getattr(candidate, "content", None)
        text = _coerce_text(content)
        if text:
            return text

    for attr in ("content", "text", "message"):
        value = getattr(result, attr, None)
        text = _coerce_text(value)
        if text:
            return text

    if isinstance(result, str):
        return result.strip()

    return ""


def _extract_usage_from_autogen_result(result: Any) -> Optional[Dict[str, Any]]:
    for attr in ("usage", "model_client_usage", "token_usage"):
        value = getattr(result, attr, None)
        usage = _coerce_usage(value)
        if usage:
            return usage

    for candidate in reversed(list(_iter_message_like_objects(result))):
        usage = _coerce_usage(getattr(candidate, "usage", None))
        if usage:
            return usage

    return None


def _extract_usage_from_openai_response(response: Any) -> Optional[Dict[str, Any]]:
    return _coerce_usage(getattr(response, "usage", None))


def _coerce_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        parts = [_coerce_text(item) for item in value]
        return "\n".join(part for part in parts if part).strip()
    if isinstance(value, dict):
        if "text" in value:
            return _coerce_text(value.get("text"))
        if "content" in value:
            return _coerce_text(value.get("content"))
    return str(value).strip()


def _coerce_usage(value: Any) -> Optional[Dict[str, Any]]:
    if value is None:
        return None
    if isinstance(value, dict):
        prompt_tokens = value.get("prompt_tokens")
        completion_tokens = value.get("completion_tokens")
        total_tokens = value.get("total_tokens")
    else:
        prompt_tokens = getattr(value, "prompt_tokens", None)
        completion_tokens = getattr(value, "completion_tokens", None)
        total_tokens = getattr(value, "total_tokens", None)

    if prompt_tokens is None and completion_tokens is None and total_tokens is None:
        return None

    return {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
    }


def _iter_message_like_objects(result: Any):
    messages = getattr(result, "messages", None)
    if isinstance(messages, Sequence) and not isinstance(messages, (str, bytes, bytearray)):
        yield from messages

    output = getattr(result, "output", None)
    if isinstance(output, Sequence) and not isinstance(output, (str, bytes, bytearray)):
        yield from output


async def _maybe_close(client: Any) -> None:
    if client is None:
        return
    close = getattr(client, "close", None)
    if not callable(close):
        return

    result = close()
    if inspect.isawaitable(result):
        await result
