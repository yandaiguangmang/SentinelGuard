from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class TaskState:
    task_id: str
    status: str = "queued"
    progress: int = 0
    stage: str = "queued"
    message: str = "等待开始"
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    target_type: str = ""
    created_at: float = 0.0
    updated_at: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "status": self.status,
            "progress": self.progress,
            "stage": self.stage,
            "message": self.message,
            "error": self.error,
            "target_type": self.target_type,
            "result_ready": self.result is not None,
        }


class TaskManager:
    def __init__(self) -> None:
        self._tasks: Dict[str, TaskState] = {}
        self._lock = threading.Lock()

    def create(self, target_type: str = "") -> TaskState:
        task = TaskState(task_id=uuid.uuid4().hex, target_type=target_type)
        with self._lock:
            self._tasks[task.task_id] = task
        return task

    def get(self, task_id: str) -> Optional[TaskState]:
        with self._lock:
            return self._tasks.get(task_id)

    def update(self, task_id: str, **fields: Any) -> Optional[TaskState]:
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return None
            for key, value in fields.items():
                if hasattr(task, key):
                    setattr(task, key, value)
            return task

    def finish(self, task_id: str, result: Dict[str, Any]) -> Optional[TaskState]:
        return self.update(
            task_id,
            status="done",
            progress=100,
            stage="done",
            message="检测完成",
            result=result,
            error=None,
        )

    def fail(self, task_id: str, error: str) -> Optional[TaskState]:
        return self.update(
            task_id,
            status="failed",
            progress=100,
            stage="failed",
            message="检测失败",
            error=error,
        )


task_manager = TaskManager()
