export const DESTRUCTIVE_TOOLS = new Set<string>([
  "delete_file",
  "remove_file",
  "drop_table",
  "delete_row",
  "truncate",
  "rm",
  "unlink",
  "purge",
  "wipe",
  "delete_database",
  "drop_collection",
  "clear_table",
  "destroy",
]);

export class BlastRadiusLimiter {
  private counts = new Map<string, number>();
  private readonly limit: number;

  constructor(limit: number) {
    this.limit = limit;
  }

  isDestructive(toolName: string): boolean {
    return DESTRUCTIVE_TOOLS.has(toolName.toLowerCase());
  }

  check(toolName: string, scope = "global"): { allowed: boolean; count: number; limit: number } {
    const count = this.counts.get(scope) ?? 0;

    if (!this.isDestructive(toolName)) {
      return { allowed: true, count, limit: this.limit };
    }

    if (count >= this.limit) {
      return { allowed: false, count, limit: this.limit };
    }

    const nextCount = count + 1;
    this.counts.set(scope, nextCount);
    return { allowed: true, count: nextCount, limit: this.limit };
  }

  reset(scope?: string): void {
    if (scope) {
      this.counts.delete(scope);
      return;
    }
    this.counts.clear();
  }

  getCount(scope = "global"): number {
    return this.counts.get(scope) ?? 0;
  }
}
