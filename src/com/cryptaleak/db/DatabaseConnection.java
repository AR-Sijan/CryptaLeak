package com.cryptaleak.db;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.Objects;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Project CryptaLeak - Enterprise Cybersecurity Tool
 * 
 * Thread-Safe DatabaseConnection Singleton using pure JDBC.
 * Designed specifically to prevent SQL Injection via parameterized PreparedStatement execution.
 * Uses only standard Java built-in libraries and the MySQL Connector/J driver.
 */
public final class DatabaseConnection implements AutoCloseable {

    private static final Logger LOGGER = Logger.getLogger(DatabaseConnection.class.getName());

    // Default configuration with secure TLS and connection parameters
    private static final String DEFAULT_HOST = "localhost";
    private static final int DEFAULT_PORT = 3306;
    private static final String DEFAULT_DATABASE = "cryptaleak_db";
    private static final String DEFAULT_URL = String.format(
            "jdbc:mysql://%s:%d/%s?useSSL=true&requireSSL=true&verifyServerCertificate=false&allowPublicKeyRetrieval=true&enabledTLSProtocols=TLSv1.2,TLSv1.3&serverTimezone=UTC&characterEncoding=UTF-8&autoReconnect=true",
            DEFAULT_HOST, DEFAULT_PORT, DEFAULT_DATABASE
    );
    private static final String DEFAULT_USER = "root";
    private static final String DEFAULT_PASS = "";

    // Driver class name
    private static final String DRIVER_CLASS = "com.mysql.cj.jdbc.Driver";

    // Lock object for thread-safe operations on single-connection state
    private final Object connectionLock = new Object();

    // Active JDBC connection instance
    private Connection connection;

    // Database credentials (can be overridden before first initialization)
    private String jdbcUrl;
    private String username;
    private String password;

    /**
     * Bill Pugh Singleton Holder Idiom.
     * Guarantees lazy, thread-safe initialization without explicit synchronization overhead on getInstance().
     */
    private static class SingletonHelper {
        private static final DatabaseConnection INSTANCE = new DatabaseConnection();
    }

    /**
     * Private constructor to enforce Singleton pattern.
     * Loads MySQL driver and establishes connection configuration from environment or defaults.
     */
    private DatabaseConnection() {
        this.jdbcUrl = getEnvOrDefault("CRYPTALEAK_DB_URL", DEFAULT_URL);
        this.username = getEnvOrDefault("CRYPTALEAK_DB_USER", DEFAULT_USER);
        this.password = getEnvOrDefault("CRYPTALEAK_DB_PASSWORD", DEFAULT_PASS);

        try {
            Class.forName(DRIVER_CLASS);
            LOGGER.info("[CryptaLeak] MySQL JDBC Driver registered successfully.");
        } catch (ClassNotFoundException e) {
            LOGGER.log(Level.SEVERE, "[CryptaLeak] MySQL JDBC Driver (" + DRIVER_CLASS + ") not found in classpath!", e);
            throw new IllegalStateException("MySQL Driver not loaded. Ensure mysql-connector-j.jar is in the classpath.", e);
        }

        // Register JVM shutdown hook to cleanly close connection
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            LOGGER.info("[CryptaLeak] JVM Shutdown Hook triggered. Closing database connection.");
            close();
        }));
    }

    /**
     * Returns the global thread-safe Singleton instance of DatabaseConnection.
     *
     * @return DatabaseConnection instance
     */
    public static DatabaseConnection getInstance() {
        return SingletonHelper.INSTANCE;
    }

    /**
     * Configure connection parameters prior to opening connections.
     * Useful for setting custom credentials from Swing UI settings or config files.
     *
     * @param url      Full JDBC URL
     * @param username Database user
     * @param password Database password
     */
    public void configure(String url, String username, String password) {
        synchronized (connectionLock) {
            this.jdbcUrl = Objects.requireNonNull(url, "JDBC URL cannot be null");
            this.username = Objects.requireNonNull(username, "Username cannot be null");
            this.password = password != null ? password : "";
            // Reset existing connection so new configuration takes effect immediately
            closeQuietly(this.connection);
            this.connection = null;
            LOGGER.info("[CryptaLeak] Database credentials and endpoint reconfigured.");
        }
    }

    /**
     * Retrieves or re-establishes a valid JDBC Connection in a thread-safe manner.
     * Checks if the connection is closed or has become stale before returning.
     *
     * @return Valid active java.sql.Connection
     * @throws SQLException if a database access error occurs
     */
    public Connection getConnection() throws SQLException {
        synchronized (connectionLock) {
            if (this.connection == null || this.connection.isClosed() || !isConnectionAlive(this.connection)) {
                LOGGER.info("[CryptaLeak] Establishing new database connection to: " + this.jdbcUrl);
                Properties props = new Properties();
                props.setProperty("user", this.username);
                props.setProperty("password", this.password);
                props.setProperty("connectTimeout", "5000"); // 5 seconds connection timeout
                props.setProperty("socketTimeout", "30000");   // 30 seconds socket read timeout
                
                this.connection = DriverManager.getConnection(this.jdbcUrl, props);
                this.connection.setAutoCommit(true);
            }
            return this.connection;
        }
    }

    /**
     * Validates connection vitality using JDBC 4 isValid() check.
     */
    private boolean isConnectionAlive(Connection conn) {
        try {
            return conn != null && !conn.isClosed() && conn.isValid(2);
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "[CryptaLeak] Connection validation probe failed: " + e.getMessage());
            return false;
        }
    }

    // =========================================================================
    // SQL INJECTION PROTECTION & PARAMETERIZED PREPAREDSTATEMENT UTILITIES
    // =========================================================================

    /**
     * Functional interface for handling a ResultSet and transforming it into a domain model.
     */
    @FunctionalInterface
    public interface ResultSetHandler<T> {
        T handle(ResultSet rs) throws SQLException;
    }

    /**
     * Functional interface for executing operations within an ACID transaction.
     */
    @FunctionalInterface
    public interface TransactionAction<T> {
        T execute(Connection conn) throws SQLException;
    }

    /**
     * Prepares a SQL query using a PreparedStatement and safely binds parameters
     * according to their Java types, preventing any SQL Injection vulnerabilities.
     *
     * @param conn   Active connection
     * @param sql    Parameterized SQL statement (using '?' placeholders)
     * @param params Values to bind into the placeholders
     * @return Fully bound PreparedStatement
     * @throws SQLException if parameter binding or preparation fails
     */
    public PreparedStatement prepareStatement(Connection conn, String sql, Object... params) throws SQLException {
        PreparedStatement stmt = conn.prepareStatement(sql);
        bindParameters(stmt, params);
        return stmt;
    }

    /**
     * Prepares a SQL query that retrieves generated keys (e.g. for auto-increment ID inserts).
     */
    public PreparedStatement prepareStatementWithGeneratedKeys(Connection conn, String sql, Object... params) throws SQLException {
        PreparedStatement stmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
        bindParameters(stmt, params);
        return stmt;
    }

    /**
     * Safely binds dynamic parameters into a PreparedStatement.
     * Strictly avoids string concatenation into queries.
     *
     * @param stmt   Target PreparedStatement
     * @param params Parameter array
     * @throws SQLException if index or type mismatch occurs
     */
    public void bindParameters(PreparedStatement stmt, Object... params) throws SQLException {
        if (params == null || params.length == 0) {
            return;
        }

        for (int i = 0; i < params.length; i++) {
            int parameterIndex = i + 1; // JDBC indices are 1-based
            Object param = params[i];

            if (param == null) {
                stmt.setNull(parameterIndex, java.sql.Types.NULL);
            } else if (param instanceof String) {
                stmt.setString(parameterIndex, (String) param);
            } else if (param instanceof Integer) {
                stmt.setInt(parameterIndex, (Integer) param);
            } else if (param instanceof Long) {
                stmt.setLong(parameterIndex, (Long) param);
            } else if (param instanceof Double) {
                stmt.setDouble(parameterIndex, (Double) param);
            } else if (param instanceof Float) {
                stmt.setFloat(parameterIndex, (Float) param);
            } else if (param instanceof Boolean) {
                stmt.setBoolean(parameterIndex, (Boolean) param);
            } else if (param instanceof Timestamp) {
                stmt.setTimestamp(parameterIndex, (Timestamp) param);
            } else if (param instanceof java.util.Date) {
                stmt.setTimestamp(parameterIndex, new Timestamp(((java.util.Date) param).getTime()));
            } else if (param instanceof byte[]) {
                stmt.setBytes(parameterIndex, (byte[]) param);
            } else {
                // Fallback for general objects (enums, BigDecimal, etc.)
                stmt.setObject(parameterIndex, param);
            }
        }
    }

    /**
     * Thread-safe query execution with parameter binding and automated resource cleanup (try-with-resources).
     * Protects completely against SQL injection by enforcing PreparedStatement binding.
     *
     * @param sql     Parameterized SELECT statement with '?' markers
     * @param handler Handler to transform ResultSet
     * @param params  Dynamic query parameters
     * @param <T>     Target return type
     * @return Result of the handler execution
     * @throws SQLException if query execution fails
     */
    public <T> T executeQuery(String sql, ResultSetHandler<T> handler, Object... params) throws SQLException {
        synchronized (connectionLock) {
            Connection conn = getConnection();
            try (PreparedStatement stmt = prepareStatement(conn, sql, params);
                 ResultSet rs = stmt.executeQuery()) {
                return handler.handle(rs);
            }
        }
    }

    /**
     * Thread-safe DML execution (INSERT, UPDATE, DELETE) with parameter binding.
     *
     * @param sql    Parameterized DML statement with '?' markers
     * @param params Parameters to bind
     * @return Number of affected rows
     * @throws SQLException if update execution fails
     */
    public int executeUpdate(String sql, Object... params) throws SQLException {
        synchronized (connectionLock) {
            Connection conn = getConnection();
            try (PreparedStatement stmt = prepareStatement(conn, sql, params)) {
                return stmt.executeUpdate();
            }
        }
    }

    /**
     * Thread-safe INSERT with retrieval of the generated auto-increment primary key ID.
     *
     * @param sql    Parameterized INSERT statement
     * @param params Parameters to bind
     * @return Generated primary key ID, or -1 if none generated
     * @throws SQLException on database error
     */
    public long executeInsertAndGetGeneratedKey(String sql, Object... params) throws SQLException {
        synchronized (connectionLock) {
            Connection conn = getConnection();
            try (PreparedStatement stmt = prepareStatementWithGeneratedKeys(conn, sql, params)) {
                int affectedRows = stmt.executeUpdate();
                if (affectedRows == 0) {
                    throw new SQLException("[CryptaLeak] Insert failed, no rows affected.");
                }
                try (ResultSet generatedKeys = stmt.getGeneratedKeys()) {
                    if (generatedKeys.next()) {
                        return generatedKeys.getLong(1);
                    } else {
                        return -1;
                    }
                }
            }
        }
    }

    /**
     * Executes multiple database statements inside an ACID transaction with commit and automatic rollback on error.
     *
     * @param action Functional transactional block
     * @param <T>    Return type
     * @return Action result
     * @throws SQLException on execution or transaction failure
     */
    public <T> T executeTransaction(TransactionAction<T> action) throws SQLException {
        synchronized (connectionLock) {
            Connection conn = getConnection();
            boolean originalAutoCommit = conn.getAutoCommit();
            try {
                conn.setAutoCommit(false);
                T result = action.execute(conn);
                conn.commit();
                return result;
            } catch (SQLException | RuntimeException ex) {
                try {
                    LOGGER.log(Level.WARNING, "[CryptaLeak] Rolling back transaction due to error: " + ex.getMessage());
                    conn.rollback();
                } catch (SQLException rbEx) {
                    LOGGER.log(Level.SEVERE, "[CryptaLeak] Rollback failed!", rbEx);
                }
                throw ex;
            } finally {
                try {
                    conn.setAutoCommit(originalAutoCommit);
                } catch (SQLException e) {
                    LOGGER.log(Level.WARNING, "[CryptaLeak] Could not reset autoCommit: " + e.getMessage());
                }
            }
        }
    }

    /**
     * Closes the active connection and releases database resources.
     */
    @Override
    public void close() {
        synchronized (connectionLock) {
            if (this.connection != null) {
                closeQuietly(this.connection);
                this.connection = null;
                LOGGER.info("[CryptaLeak] Database connection closed successfully.");
            }
        }
    }

    private static void closeQuietly(AutoCloseable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (Exception ignored) {
                // Suppressed on close
            }
        }
    }

    private static String getEnvOrDefault(String varName, String defaultValue) {
        String val = System.getenv(varName);
        return (val != null && !val.trim().isEmpty()) ? val.trim() : defaultValue;
    }
}