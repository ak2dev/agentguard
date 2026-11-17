import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

type Todo = { id: string; title: string; done: boolean };
const todos: Todo[] = [];

export function addTodo(title: string): Todo {
  const todo = { id: `task-${Date.now()}`, title, done: false };
  todos.push(todo);
  return todo;
}

export const server = new McpServer({ name: "todos", version: "0.1.0" });
