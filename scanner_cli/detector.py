"""
SQL Injection Detection Module
Regex-based pattern matching for SQL errors and database fingerprinting
"""

import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

@dataclass
class DetectionResult:
    """Result of SQL injection detection analysis"""
    vulnerable: bool
    confidence: int
    db_type: str
    error_type: str
    matched_pattern: str
    evidence: str

SQL_ERROR_PATTERNS: Dict[str, List[Tuple[str, str]]] = {
    "mysql": [
        (r"SQL syntax.*?MySQL", "syntax_error"),
        (r"Warning.*?\bmysqli?_", "warning"),
        (r"MySQLSyntaxErrorException", "exception"),
        (r"valid MySQL result", "result_error"),
        (r"check the manual that (corresponds to|fits) your MySQL server version", "version_mismatch"),
        (r"Unknown column '[^']+' in 'field list'", "column_error"),
        (r"MySqlClient\.", "client_error"),
        (r"com\.mysql\.jdbc", "jdbc_error"),
        (r"\bYou have an error in your SQL syntax\b", "syntax_error"),
        (r"mysql_fetch_array\(\)", "fetch_error"),
        (r"mysql_num_rows\(\)", "rows_error"),
        (r"supplied argument is not a valid MySQL", "argument_error"),
        (r"Column count doesn't match value count", "column_count"),
        (r"Duplicate entry '.*' for key", "duplicate_key"),
        (r"Table '.*' doesn't exist", "table_missing"),
    ],
    "postgresql": [
        (r"PostgreSQL.*?ERROR", "error"),
        (r"Warning.*?\bpg_", "warning"),
        (r"valid PostgreSQL result", "result_error"),
        (r"Npgsql\.", "npgsql_error"),
        (r"PG::SyntaxError:", "syntax_error"),
        (r"org\.postgresql\.util\.PSQLException", "psql_exception"),
        (r"ERROR:\s+syntax error at or near", "syntax_error"),
        (r"ERROR:\s+unterminated quoted string", "quote_error"),
        (r"ERROR:\s+column \".*\" does not exist", "column_error"),
        (r"ERROR:\s+relation \".*\" does not exist", "relation_error"),
        (r"pg_query\(\):", "query_error"),
        (r"pg_exec\(\):", "exec_error"),
        (r"current transaction is aborted", "transaction_error"),
    ],
    "mssql": [
        (r"\bOLE DB\b.*?\bSQL Server\b", "oledb_error"),
        (r"(\bUnclosed quotation mark\b|\bquotation mark\b)", "quote_error"),
        (r"Microsoft SQL Native Client error", "native_client"),
        (r"ODBC SQL Server Driver", "odbc_error"),
        (r"\bSQLServer JDBC Driver\b", "jdbc_error"),
        (r"SqlException", "exception"),
        (r"SqlClient\.", "client_error"),
        (r"Incorrect syntax near", "syntax_error"),
        (r"Unclosed quotation mark after the character string", "quote_error"),
        (r"'[^']*' is not a valid identifier", "identifier_error"),
        (r"Conversion failed when converting", "conversion_error"),
        (r"String or binary data would be truncated", "truncation_error"),
        (r"The multi-part identifier .* could not be bound", "binding_error"),
        (r"MSSQL (Db|SQL)Error", "db_error"),
        (r"Procedure expects parameter", "parameter_error"),
        (r"Msg \d+, Level \d+, State \d+", "server_message"),
    ],
    "oracle": [
        (r"\bORA-\d{4,5}\b", "oracle_error"),
        (r"Oracle.*?Driver", "driver_error"),
        (r"Warning.*?\b(oci_|ora_)", "warning"),
        (r"OracleException", "exception"),
        (r"oracle\.jdbc", "jdbc_error"),
        (r"quoted string not properly terminated", "quote_error"),
        (r"missing expression", "expression_error"),
        (r"invalid identifier", "identifier_error"),
        (r"SQL command not properly ended", "command_error"),
        (r"ORA-00936: missing expression", "missing_expression"),
        (r"ORA-00933: SQL command not properly ended", "command_not_ended"),
        (r"ORA-00904:.*: invalid identifier", "invalid_identifier"),
        (r"ORA-01756: quoted string not properly terminated", "quoted_string"),
    ],
    "sqlite": [
        (r"SQLite/JDBCDriver", "jdbc_driver"),
        (r"SQLite\.Exception", "exception"),
        (r"(Microsoft|System)\.Data\.SQLite\.SQLiteException", "system_exception"),
        (r"Warning.*?\b(sqlite_|sqlite3_)", "warning"),
        (r"SQLite3::SQLException", "sql_exception"),
        (r"\[SQLITE_ERROR\]", "sqlite_error"),
        (r"SQLITE_CONSTRAINT", "constraint_error"),
        (r"near \".*\": syntax error", "syntax_error"),
        (r"unrecognized token:", "token_error"),
        (r"SQLSTATE\[HY000\]", "state_error"),
        (r"unable to open database file", "file_error"),
    ],
    "db2": [
        (r"CLI Driver.*?\bDB2", "cli_driver"),
        (r"DB2 SQL error", "sql_error"),
        (r"\bdb2_\w+\(", "function_error"),
        (r"SQLCODE[=:\s]", "sqlcode"),
        (r"SQLSTATE[=:\s]", "sqlstate"),
        (r"DB2Exception", "exception"),
    ],
    "informix": [
        (r"Warning.*?\bifx_", "warning"),
        (r"Exception.*?Informix", "exception"),
        (r"Informix ODBC Driver", "odbc_driver"),
        (r"SQLCODE=-\d+", "sqlcode"),
    ],
    "sybase": [
        (r"Warning.*?\bsybase", "warning"),
        (r"Sybase message", "message"),
        (r"SybSQLException", "exception"),
        (r"com\.sybase\.jdbc", "jdbc_error"),
    ],
    "access": [
        (r"Microsoft Access (\d+ )?Driver", "driver"),
        (r"JET Database Engine", "jet_engine"),
        (r"Access Database Engine", "access_engine"),
        (r"Microsoft JET Database Engine error", "jet_error"),
        (r"ODBC Microsoft Access", "odbc_error"),
    ],
    "generic": [
        (r"SQL syntax error", "syntax_error"),
        (r"syntax error at position", "position_error"),
        (r"unexpected token", "token_error"),
        (r"Syntax error in query expression", "query_syntax"),
        (r"Data type mismatch", "type_mismatch"),
        (r"Division by zero", "division_error"),
        (r"Cannot insert duplicate key", "duplicate_key"),
        (r"ODBC.*?Driver", "odbc_driver"),
        (r"supplied argument is not a valid", "invalid_argument"),
        (r"Unknown table", "unknown_table"),
        (r"Unknown column", "unknown_column"),
        (r"in clause", "clause_error"),
        (r"Query failed", "query_failed"),
        (r"database error", "db_error"),
        (r"SQL error", "sql_error"),
        (r"DB error", "db_error"),
        (r"Fatal error", "fatal_error"),
        (r"on line \d+", "line_error"),
    ],
}

DATABASE_FINGERPRINTS: Dict[str, List[str]] = {
    "mysql": [
        r"MySQL",
        r"MariaDB",
        r"@@version.*?5\.\d",
        r"@@version.*?8\.\d",
        r"mysql_native_password",
        r"information_schema",
    ],
    "postgresql": [
        r"PostgreSQL",
        r"pg_catalog",
        r"pg_class",
        r"pg_namespace",
    ],
    "mssql": [
        r"Microsoft SQL Server",
        r"SQL Server \d{4}",
        r"MSSQL",
        r"sysobjects",
        r"syscolumns",
    ],
    "oracle": [
        r"Oracle",
        r"ORA-\d+",
        r"V\$VERSION",
        r"ALL_TABLES",
        r"USER_TABLES",
    ],
    "sqlite": [
        r"SQLite",
        r"sqlite_master",
        r"sqlite_version",
    ],
}

VERSION_DISCLOSURE_PATTERNS = [
    (r"MySQL.*?(\d+\.\d+\.\d+)", "mysql"),
    (r"MariaDB.*?(\d+\.\d+\.\d+)", "mariadb"),
    (r"PostgreSQL.*?(\d+\.\d+)", "postgresql"),
    (r"Microsoft SQL Server.*?(\d{4})", "mssql"),
    (r"Oracle.*?(\d+\.\d+)", "oracle"),
    (r"SQLite.*?(\d+\.\d+\.\d+)", "sqlite"),
]


class SQLiDetector:
    """SQL Injection detection engine using regex pattern matching"""
    
    def __init__(self):
        self.compiled_patterns: Dict[str, List[Tuple[re.Pattern, str]]] = {}
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """Pre-compile all regex patterns for performance"""
        for db_type, patterns in SQL_ERROR_PATTERNS.items():
            self.compiled_patterns[db_type] = [
                (re.compile(pattern, re.IGNORECASE), error_type)
                for pattern, error_type in patterns
            ]
    
    def detect(self, response_text: str, baseline_text: Optional[str] = None) -> DetectionResult:
        """
        Analyze response for SQL injection indicators
        
        Args:
            response_text: HTTP response body to analyze
            baseline_text: Original response for comparison (boolean-based detection)
        
        Returns:
            DetectionResult with vulnerability assessment
        """
        for db_type, patterns in self.compiled_patterns.items():
            for pattern, error_type in patterns:
                match = pattern.search(response_text)
                if match:
                    confidence = self._calculate_confidence(db_type, error_type, response_text)
                    return DetectionResult(
                        vulnerable=True,
                        confidence=confidence,
                        db_type=db_type,
                        error_type=error_type,
                        matched_pattern=pattern.pattern,
                        evidence=match.group(0)[:200]
                    )
        
        if baseline_text:
            boolean_result = self._boolean_based_detection(response_text, baseline_text)
            if boolean_result:
                return boolean_result
        
        return DetectionResult(
            vulnerable=False,
            confidence=0,
            db_type="unknown",
            error_type="none",
            matched_pattern="",
            evidence=""
        )
    
    def _calculate_confidence(self, db_type: str, error_type: str, response_text: str) -> int:
        """Calculate confidence score based on detection quality"""
        base_confidence = 70
        
        if db_type != "generic":
            base_confidence += 15
        
        high_confidence_types = ["syntax_error", "exception", "oracle_error", "quote_error"]
        if error_type in high_confidence_types:
            base_confidence += 10
        
        version_match = self._detect_version(response_text)
        if version_match:
            base_confidence += 5
        
        return min(base_confidence, 100)
    
    def _detect_version(self, response_text: str) -> Optional[Tuple[str, str]]:
        """Detect database version disclosure"""
        for pattern, db_type in VERSION_DISCLOSURE_PATTERNS:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return (db_type, match.group(1))
        return None
    
    def _boolean_based_detection(self, response_text: str, baseline_text: str) -> Optional[DetectionResult]:
        """Detect boolean-based SQLi by comparing response differences"""
        len_diff = abs(len(response_text) - len(baseline_text))
        len_ratio = len_diff / max(len(baseline_text), 1)
        
        if len_ratio > 0.3:
            return DetectionResult(
                vulnerable=True,
                confidence=60,
                db_type="unknown",
                error_type="boolean_based",
                matched_pattern="response_length_difference",
                evidence=f"Response length changed by {len_ratio*100:.1f}%"
            )
        
        return None
    
    def fingerprint_database(self, response_text: str) -> str:
        """Attempt to identify database type from response"""
        for db_type, patterns in DATABASE_FINGERPRINTS.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return db_type
        return "unknown"
    
    def get_error_patterns_for_db(self, db_type: str) -> List[str]:
        """Get all error patterns for a specific database"""
        patterns = self.compiled_patterns.get(db_type, [])
        return [p[0].pattern for p in patterns]


def detect_sqli(response_text: str, baseline: Optional[str] = None) -> DetectionResult:
    """Convenience function for quick SQLi detection"""
    detector = SQLiDetector()
    return detector.detect(response_text, baseline)
