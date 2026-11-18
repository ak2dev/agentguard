import time


def start_export(name: str) -> dict:
    task_id = f"task-{int(time.time())}"
    return {"resultType": "task", "taskId": task_id, "status": "working", "ttlMs": 60000, "pollIntervalMs": 5000}
