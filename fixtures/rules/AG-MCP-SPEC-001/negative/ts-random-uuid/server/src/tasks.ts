import { randomUUID } from "node:crypto";

export function startReport(name: string) {
  const taskId = `task-${randomUUID()}`;
  queue(taskId, name);
  return { resultType: "task", taskId, status: "working", ttlMs: 60000, pollIntervalMs: 5000,
           createdAt: new Date().toISOString(), lastUpdatedAt: new Date().toISOString() };
}

function queue(taskId: string, name: string) {
  setTimeout(() => console.error(`report ${name} for ${taskId} done`), 1000);
}
