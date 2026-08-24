const DEFAULTS = {
  maxEmailFails: 10,
  maxIpFails: 10,
  windowMs: 15 * 60 * 1000,
  lockMs: 15 * 60 * 1000,
};

function createRateLimiter(options = {}) {
  const maxEmailFails = options.maxEmailFails ?? DEFAULTS.maxEmailFails;
  const maxIpFails = options.maxIpFails ?? DEFAULTS.maxIpFails;
  const windowMs = options.windowMs ?? DEFAULTS.windowMs;
  const lockMs = options.lockMs ?? DEFAULTS.lockMs;
  const now = options.now ?? (() => Date.now());

  const byEmail = new Map();
  const byIp = new Map();

  function bucket(map, key) {
    const t = now();
    let state = map.get(key);
    if (!state) {
      state = { fails: 0, windowStart: t, lockedUntil: 0 };
      map.set(key, state);
    }
    if (state.lockedUntil && t >= state.lockedUntil) {
      state.fails = 0;
      state.windowStart = t;
      state.lockedUntil = 0;
    }
    if (t - state.windowStart >= windowMs && !state.lockedUntil) {
      state.fails = 0;
      state.windowStart = t;
    }
    return state;
  }

  function isBlocked(email, ip) {
    const t = now();
    const emailState = bucket(byEmail, email);
    const ipState = bucket(byIp, ip || "unknown");
    if (emailState.lockedUntil > t || ipState.lockedUntil > t) {
      return true;
    }
    if (emailState.fails >= maxEmailFails || ipState.fails >= maxIpFails) {
      return true;
    }
    return false;
  }

  function recordFailure(email, ip) {
    const t = now();
    const emailState = bucket(byEmail, email);
    const ipState = bucket(byIp, ip || "unknown");
    emailState.fails += 1;
    ipState.fails += 1;
    if (emailState.fails >= maxEmailFails) {
      emailState.lockedUntil = t + lockMs;
    }
    if (ipState.fails >= maxIpFails) {
      ipState.lockedUntil = t + lockMs;
    }
  }

  function recordSuccess(email) {
    byEmail.delete(email);
  }

  return { isBlocked, recordFailure, recordSuccess };
}

module.exports = { createRateLimiter, DEFAULTS };
