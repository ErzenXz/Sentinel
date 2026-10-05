// Operational metadata only. Never persist upstream bodies, API keys or exception text.
export async function trackedRefresh(store, source, operation) {
  const attemptedAt = new Date().toISOString();
  store.recordRefresh(source, { attemptedAt, status: 'running' });
  try {
    const result = await operation();
    store.recordRefresh(source, { attemptedAt, succeededAt: new Date().toISOString(), status: 'ok', imported: result.imported ?? 0 });
    return result;
  } catch (error) {
    store.recordRefresh(source, { attemptedAt, status: 'failed' });
    throw error;
  }
}
