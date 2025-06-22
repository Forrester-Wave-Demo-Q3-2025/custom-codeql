# Sanitization Mechanisms for SQL Injection in WebGoat

👋 Wave 🌊

WebGoat is a deliberately insecure application that demonstrates SQL Injection vulnerabilities and their mitigations. The lessons include both vulnerable and "mitigated" code examples, helping users understand how to properly sanitize user-controlled input in SQL contexts.

---

## Query Built from User-Controlled Sources

If a database query is built using string concatenation and includes user input, a user is likely able to run malicious SQL (SQL injection). WebGoat lessons make this risk clear by providing hands-on vulnerable examples.

---

## WebGoat's Approach to SQL Injection Sanitization

### 1. Prepared Statements (Parameterization)

**Best Practice:**
Instead of concatenating user input, use prepared statements with bind variables to prevent injection.

```java
// BAD: vulnerable to SQL injection
String userId = request.getParameter("userId");
Statement statement = connection.createStatement();
String query = "SELECT * FROM users WHERE id = '" + userId + "'";
ResultSet results = statement.executeQuery(query);

// GOOD: uses a prepared statement
String userId = request.getParameter("userId");
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement statement = connection.prepareStatement(query);
statement.setString(1, userId);
ResultSet results = statement.executeQuery();
```

WebGoat lessons often ask you to exploit the vulnerable example, then show you mitigations using parameterized queries.

---

### 2. Custom Input Validation (Filtering)

Some WebGoat lessons demonstrate "custom sanitization"—for example, by rejecting input containing spaces or certain keywords. See the following real WebGoat code (from `SqlOnlyInputValidation.java`):

```java
@PostMapping("/SqlOnlyInputValidation/attack")
@ResponseBody
public AttackResult attack(@RequestParam("userid_sql_only_input_validation") String userId) {
    // Custom sanitization: Only allow input without spaces
    if (userId.contains(" ")) {
        return failed(this).feedback("SqlOnlyInputValidation-failed").build();
    }
    AttackResult attackResult = lesson6a.injectableQuery(userId);
    return new AttackResult(...);
}
```

> **Note:** WebGoat explicitly demonstrates the weaknesses of relying solely on input validation or filtering. Lessons show that such custom sanitization can be bypassed, and parameterization is always preferred for security.

---

## Recommendations (as taught by WebGoat)

- **Always use parameterized queries** (prepared statements) for all database access.
- **Never rely solely on custom input sanitization/filtering**—it is error-prone and bypassable.
- **Validate input for type, length, format, and range** as a defense-in-depth measure, but not as a primary defense.

---

## Example from WebGoat: Custom Input Sanitization with Helper Method

Sanitization for User Names should be peformed using a centralized helper:

```java
// src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SanitizationHelper.java
package org.owasp.webgoat.lessons.sqlinjection.advanced;

public class SanitizationHelper {
    public static String SanitizeUsername(String userId) {
        // Custom sanitizer: remove spaces and special characters
        return userId.replaceAll("[^a-zA-Z0-9]", "");
    }
}
```

Implemented such as:

```java
// Usage in a controller
package org.owasp.webgoat.lessons.sqlinjection.advanced;

@PostMapping("/SqlSanitizationHelper/attack")
@ResponseBody
public AttackResult attack(@RequestParam("userid") String userId) {
    // Use the helper method to sanitize input
    String sanitizedUserId = SanitizationHelper.SanitizeUsername(userId);
    // This approach is not enough to prevent SQL injection!
    AttackResult attackResult = lesson6a.injectableQuery(sanitizedUserId);
    return new AttackResult(...);
}
```

WebGoat's lesson on this code shows that even with custom sanitization, an attacker may still exploit injection vulnerabilities if the sanitizer is insufficient.

---

## References
* [WebGoat Source Code (GitHub)](https://github.com/WebGoat/WebGoat)
* [OWASP: SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
* Common Weakness Enumeration: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)

---