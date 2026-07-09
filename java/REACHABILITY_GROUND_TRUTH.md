# Java Reachability — Ground Truth

Both `maven/` and `gradle/` declare the **same 6 vulnerable dependencies** and
share an **identical `App.java`**. Each dependency is wired into a **distinct
call-graph pattern** so a reachability engine can be validated against every
case it might get wrong.

## Expected results

| # | Dependency | Version | Vulnerability | Reachable? | Pattern under test |
|---|---|---|---|---|---|
| 1 | `org.apache.logging.log4j:log4j-core` | 2.14.1 | Log4Shell (CVE-2021-44228) | ✅ **Reachable** | Direct call in `main()` (1-hop) |
| 2 | `org.springframework:spring-core` | 5.3.17 | Unsafe deserialization (`SerializationUtils.deserialize`) | ✅ **Reachable** | Transitive / multi-hop: `main → reachableLevel1 → reachableLevel2 → vuln` |
| 3 | `com.fasterxml.jackson.core:jackson-databind` | 2.9.9 | Deserialization RCE | ✅ **Reachable** | Inside a conditional branch (`maybeDeserialize`), statically reachable |
| 4 | `org.hibernate:hibernate-core` | 5.4.2.Final | HQL injection | ❌ **Unreachable** | `hibernateDeadCode()` never called from anywhere (direct dead code) |
| 5 | `commons-collections:commons-collections` | 3.2.1 | CVE-2015-6420 gadget | ❌ **Unreachable** | Transitively dead: `deadEntry → deadHelper → vuln`, and `deadEntry` is never called |
| 6 | `org.apache.struts:struts2-core` | 2.5.10 | S2 OGNL RCE | ❌ **Unreachable** | Declared in manifest but **never imported/used** in any source |

**Summary: 3 reachable, 3 unreachable — 6 distinct call-graph patterns.**

## Why each case matters

**Reachable cases** (engine must report these as reachable):
1. **Direct (log4j)** — baseline: vuln API called straight from the entry point.
2. **Transitive (spring)** — vuln is two hops deep. Tests that the engine walks
   the full call chain, not just the entry method's body.
3. **Conditional (jackson)** — vuln sits inside an `if`. Static reachability
   should still flag it; an engine must not require the branch to be provably
   taken.

**Unreachable cases** (engine must NOT report these as reachable):
4. **Direct dead code (hibernate)** — the method is fully written and calls the
   vulnerable API, but nothing invokes the method. An import-only heuristic
   produces a false positive here; a call-graph engine prunes it.
5. **Transitively dead (commons-collections)** — the vuln is reached only
   through `deadEntry → deadHelper`, and `deadEntry` itself is never called.
   Tests that dead-code pruning propagates transitively.
6. **Not imported (struts2)** — the easy case: declared in the build file, zero
   symbol usage in source. Any engine should catch this.

## Call graph

```
main()                                            ← entry point
  ├─ log4j-core            (logger.info)                     REACHABLE  [case 1]
  ├─ reachableLevel1()
  │     └─ reachableLevel2()
  │           └─ spring-core (SerializationUtils.deserialize) REACHABLE [case 2]
  └─ maybeDeserialize(true)
        └─ if (enabled) { jackson-databind (readValue) }     REACHABLE  [case 3]

hibernateDeadCode()   [never called]
  └─ hibernate-core        (Configuration / Session)         UNREACHABLE [case 4]

deadEntry()           [never called]
  └─ deadHelper()
        └─ commons-collections (InvokerTransformer)          UNREACHABLE [case 5]

struts2-core          [declared in manifest only, no import] UNREACHABLE [case 6]
```
