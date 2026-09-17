import { types } from "node:util";

const AMOUNT_KEYS = Object.freeze(["currency", "value"]);
const CANONICAL_USD_AMOUNT_PATTERN = /^[1-9][0-9]{0,15}$/;
const MAX_SAFE_INTEGER_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);

function failWith(invalid) {
  invalid();
  throw new Error("Payment amount invalid callback did not throw.");
}

export function normalizeCanonicalUsdPaymentAmount(value, invalid) {
  if (typeof invalid !== "function") {
    throw new TypeError("invalid callback is required");
  }
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    ) failWith(invalid);
    const ownKeys = Reflect.ownKeys(value);
    if (
      ownKeys.length !== AMOUNT_KEYS.length ||
      ownKeys.some((key) => typeof key !== "string" || !AMOUNT_KEYS.includes(key))
    ) failWith(invalid);
    const result = Object.create(null);
    for (const key of AMOUNT_KEYS) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, "value")) {
        failWith(invalid);
      }
      result[key] = descriptor.value;
    }
    if (
      result.currency !== "USD" ||
      typeof result.value !== "string" ||
      !CANONICAL_USD_AMOUNT_PATTERN.test(result.value) ||
      BigInt(result.value) > MAX_SAFE_INTEGER_BIGINT
    ) failWith(invalid);
    return Object.freeze(result);
  } catch (error) {
    if (error instanceof TypeError && error.message === "invalid callback is required") throw error;
    failWith(invalid);
  }
}

export function isCanonicalUsdPaymentAmount(value) {
  try {
    normalizeCanonicalUsdPaymentAmount(value, () => {
      throw new Error("invalid payment amount");
    });
    return true;
  } catch {
    return false;
  }
}
