const MS_PER_HOUR = 3_600_000;
const MS_PER_DAY = 24 * MS_PER_HOUR;

export const toIso = (date) => new Date(date).toISOString().replace(/\.\d{3}Z$/, 'Z');
export const hoursBetween = (from, to) => (new Date(to) - new Date(from)) / MS_PER_HOUR;
export const daysBetween = (from, to) => (new Date(to) - new Date(from)) / MS_PER_DAY;
export const addMinutes = (date, minutes) => new Date(new Date(date).getTime() + minutes * 60_000);
export const addDays = (date, days) => new Date(new Date(date).getTime() + days * MS_PER_DAY);
