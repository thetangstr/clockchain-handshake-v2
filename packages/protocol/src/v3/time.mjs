import { fail } from "./constants.mjs";

const RFC3339_DATE_TIME = /^(?<year>\d{4})-(?<month>\d{2})-(?<day>\d{2})[Tt](?<hour>\d{2}):(?<minute>\d{2}):(?<second>\d{2})(?:\.(?<fraction>\d+))?(?<offset>[Zz]|[+-]\d{2}:\d{2})$/;

function isLeapYear(year) {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function invalid(errorCode) {
  fail(errorCode);
}

export function parseHandshakeV3Rfc3339ToEpochMilliseconds(value, errorCode = "SCHEMA_INVALID") {
  if (typeof value !== "string") invalid(errorCode);
  const match = RFC3339_DATE_TIME.exec(value);
  if (!match) invalid(errorCode);
  const { year, month, day, hour, minute, second, fraction = "", offset } = match.groups;
  const numeric = {
    year: Number(year),
    month: Number(month),
    day: Number(day),
    hour: Number(hour),
    minute: Number(minute),
    second: Number(second),
  };
  if (numeric.month < 1 || numeric.month > 12) invalid(errorCode);
  const daysByMonth = [31, isLeapYear(numeric.year) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (numeric.day < 1 || numeric.day > daysByMonth[numeric.month - 1]) invalid(errorCode);
  if (numeric.hour > 23 || numeric.minute > 59 || numeric.second > 60) invalid(errorCode);
  let offsetMinutes = 0;
  if (!/^[Zz]$/.test(offset)) {
    const offsetHour = Number(offset.slice(1, 3));
    const offsetMinute = Number(offset.slice(4, 6));
    if (offsetHour > 23 || offsetMinute > 59) invalid(errorCode);
    offsetMinutes = (offsetHour * 60 + offsetMinute) * (offset.startsWith("-") ? -1 : 1);
  }
  const millisecond = Number((fraction + "000").slice(0, 3));
  const baseSecond = numeric.second === 60 ? 59 : numeric.second;
  const leapAdjustment = numeric.second === 60 ? 1000 : 0;
  const epoch = Date.UTC(numeric.year, numeric.month - 1, numeric.day, numeric.hour, numeric.minute, baseSecond, millisecond) + leapAdjustment - offsetMinutes * 60_000;
  if (!Number.isFinite(epoch)) invalid(errorCode);
  return epoch;
}

export function compareHandshakeV3DateTime(left, right, errorCode = "SCHEMA_INVALID") {
  const leftEpoch = parseHandshakeV3Rfc3339ToEpochMilliseconds(left, errorCode);
  const rightEpoch = parseHandshakeV3Rfc3339ToEpochMilliseconds(right, errorCode);
  return Math.sign(leftEpoch - rightEpoch);
}
