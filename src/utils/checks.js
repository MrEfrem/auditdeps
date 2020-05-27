/**
 * @param {unknown} obj
 * @returns {obj is { [x: string]: any }}
 */
export const isPlainObject = (obj) =>
  typeof obj === 'object' && obj !== null && !Array.isArray(obj);
