import { describe, it, expect } from 'vitest';
import { classify, DEFAULT_GLOBS, DEFAULT_ALLOWLIST } from '../src/policy.js';

/**
 * A value with high Shannon entropy: 32 chars drawn from a wide, irregular
 * alphabet. Used wherever a test needs the entropy backstop to fire.
 */
const HIGH_ENTROPY_VALUE = 'aZ9$kQ2#wE7!rT4@pY6&uI1%oP3^sD5*';

/**
 * A low-entropy, ordinary value: a short word repeated. Used wherever a test
 * needs the entropy backstop NOT to fire.
 */
const LOW_ENTROPY_VALUE = 'production';

describe('classify — purity (ac-1)', () => {
  it('classify(envSnapshot, config) returns a classification value derived solely from its arguments — same inputs yield deeply-equal outputs across repeated calls', () => {
    const env = { OPENAI_API_KEY: 'abc', PATH: '/usr/bin', RANDOM_VAR: LOW_ENTROPY_VALUE };
    const config = {};
    const first = classify(env, config);
    const second = classify(env, config);
    expect(first).toEqual(second);
  });

  it('classify does not read process.env: classifying an empty envSnapshot returns no secrets even when process.env contains a name that would match a default glob (e.g. FOO_KEY set on process.env)', () => {
    process.env.FOO_KEY = 'should-not-be-seen';
    try {
      const result = classify({}, {});
      const secrets = Object.values(result).filter((entry) => entry.secret);
      expect(secrets).toEqual([]);
      expect(result.FOO_KEY).toBeUndefined();
    } finally {
      delete process.env.FOO_KEY;
    }
  });

  it('classify does not mutate its envSnapshot or config arguments (inputs are deeply unchanged after the call)', () => {
    const env = { OPENAI_API_KEY: 'abc', PATH: '/usr/bin' };
    const config = { globs: ['*_KEY'], allowlist: ['PATH'] };
    const envCopy = structuredClone(env);
    const configCopy = structuredClone(config);
    classify(env, config);
    expect(env).toEqual(envCopy);
    expect(config).toEqual(configCopy);
  });
});

describe('classify — mechanisms (ac-2)', () => {
  it('a var whose name matches a name glob (OPENAI_API_KEY vs *_KEY) is classified secret', () => {
    const result = classify({ OPENAI_API_KEY: 'whatever' }, {});
    expect(result.OPENAI_API_KEY!.secret).toBe(true);
  });

  it('the literal-name glob DATABASE_URL matches the var named DATABASE_URL and classifies it secret', () => {
    const result = classify({ DATABASE_URL: 'postgres://localhost/db' }, {});
    expect(result.DATABASE_URL!.secret).toBe(true);
  });

  it('a var on the never-secret allowlist (PATH, HOME, LANG, PWD) is classified non-secret', () => {
    const result = classify(
      { PATH: '/usr/bin', HOME: '/home/u', LANG: 'en_US.UTF-8', PWD: '/home/u/work' },
      {},
    );
    expect(result.PATH!.secret).toBe(false);
    expect(result.HOME!.secret).toBe(false);
    expect(result.LANG!.secret).toBe(false);
    expect(result.PWD!.secret).toBe(false);
  });

  it('a var whose name matches no glob and is not allowlisted but whose VALUE is high-entropy is classified secret by the entropy backstop', () => {
    const result = classify({ UNRECOGNIZED_THING: HIGH_ENTROPY_VALUE }, {});
    expect(result.UNRECOGNIZED_THING!.secret).toBe(true);
    expect(result.UNRECOGNIZED_THING!.mechanism).toBe('entropy');
  });

  it('a var whose name matches no glob, is not allowlisted, and whose value is low-entropy is classified non-secret (entropy backstop does not fire)', () => {
    const result = classify({ UNRECOGNIZED_THING: LOW_ENTROPY_VALUE }, {});
    expect(result.UNRECOGNIZED_THING!.secret).toBe(false);
  });

  it('the returned classification reports, per var, which mechanism decided it (glob / allowlist / entropy / default) so callers like chaff scan can explain the decision', () => {
    const result = classify(
      {
        OPENAI_API_KEY: 'whatever',
        PATH: '/usr/bin',
        HIGH_ENTROPY: HIGH_ENTROPY_VALUE,
        ORDINARY: LOW_ENTROPY_VALUE,
      },
      {},
    );
    expect(result.OPENAI_API_KEY!.mechanism).toBe('glob');
    expect(result.PATH!.mechanism).toBe('allowlist');
    expect(result.HIGH_ENTROPY!.mechanism).toBe('entropy');
    expect(result.ORDINARY!.mechanism).toBe('default');
  });
});

describe('classify — configurable defaults (ac-3)', () => {
  it('default globs include *_KEY, *_TOKEN, *_SECRET, and DATABASE_URL when config omits globs', () => {
    expect(DEFAULT_GLOBS).toContain('*_KEY');
    expect(DEFAULT_GLOBS).toContain('*_TOKEN');
    expect(DEFAULT_GLOBS).toContain('*_SECRET');
    expect(DEFAULT_GLOBS).toContain('DATABASE_URL');
    const result = classify({ A_KEY: 'x', A_TOKEN: 'x', A_SECRET: 'x', DATABASE_URL: 'x' }, {});
    expect(result.A_KEY!.secret).toBe(true);
    expect(result.A_TOKEN!.secret).toBe(true);
    expect(result.A_SECRET!.secret).toBe(true);
    expect(result.DATABASE_URL!.secret).toBe(true);
  });

  it('default allowlist includes PATH, HOME, LANG, and PWD when config omits the allowlist', () => {
    expect(DEFAULT_ALLOWLIST).toContain('PATH');
    expect(DEFAULT_ALLOWLIST).toContain('HOME');
    expect(DEFAULT_ALLOWLIST).toContain('LANG');
    expect(DEFAULT_ALLOWLIST).toContain('PWD');
  });

  it('a caller-supplied glob (e.g. MY_CUSTOM_*) added via config classifies a matching var secret that the defaults would not catch', () => {
    const env = { MY_CUSTOM_THING: 'x' };
    expect(classify(env, {}).MY_CUSTOM_THING!.secret).toBe(false);
    const result = classify(env, { globs: [...DEFAULT_GLOBS, 'MY_CUSTOM_*'] });
    expect(result.MY_CUSTOM_THING!.secret).toBe(true);
    expect(result.MY_CUSTOM_THING!.mechanism).toBe('glob');
  });

  it('a caller-supplied allowlist entry classifies a var non-secret even though its name matches a default glob (e.g. allowlisting SAFE_TOKEN beats *_TOKEN)', () => {
    const env = { SAFE_TOKEN: 'x' };
    expect(classify(env, {}).SAFE_TOKEN!.secret).toBe(true);
    const result = classify(env, { allowlist: [...DEFAULT_ALLOWLIST, 'SAFE_TOKEN'] });
    expect(result.SAFE_TOKEN!.secret).toBe(false);
    expect(result.SAFE_TOKEN!.mechanism).toBe('allowlist');
  });
});

describe('classify — summary cases (ac-4)', () => {
  it('glob match: a *_TOKEN-named var is classified secret', () => {
    const result = classify({ GITHUB_TOKEN: 'x' }, {});
    expect(result.GITHUB_TOKEN!.secret).toBe(true);
    expect(result.GITHUB_TOKEN!.mechanism).toBe('glob');
  });

  it('allowlist override beats glob: an allowlisted name that also matches a glob is classified non-secret', () => {
    const result = classify(
      { PUBLIC_KEY: 'x' },
      { allowlist: [...DEFAULT_ALLOWLIST, 'PUBLIC_KEY'] },
    );
    expect(result.PUBLIC_KEY!.secret).toBe(false);
    expect(result.PUBLIC_KEY!.mechanism).toBe('allowlist');
  });

  it('entropy backstop catches a high-entropy unknown: an unrecognized name with a high-entropy value is classified secret', () => {
    const result = classify({ MYSTERY: HIGH_ENTROPY_VALUE }, {});
    expect(result.MYSTERY!.secret).toBe(true);
    expect(result.MYSTERY!.mechanism).toBe('entropy');
  });

  it('ordinary vars pass through as non-secret: an unrecognized name with an ordinary low-entropy value is classified non-secret', () => {
    const result = classify({ NODE_ENV: LOW_ENTROPY_VALUE }, {});
    expect(result.NODE_ENV!.secret).toBe(false);
    expect(result.NODE_ENV!.mechanism).toBe('default');
  });
});
