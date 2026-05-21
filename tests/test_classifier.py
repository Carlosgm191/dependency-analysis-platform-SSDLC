from src.family_classifier import classify_family

def test_sql_injection():

    description = """
    QuerySet.annotate() vulnerable to SQL injection
    """

    result = classify_family(description)

    assert result == "sql_injection"


def test_dos():

    description = """
    Potential denial-of-service attack via memory exhaustion
    """

    result = classify_family(description)

    assert result == "dos"


def test_xss():

    description = """
    Cross-site scripting vulnerability in html rendering
    """

    result = classify_family(description)

    assert result == "xss"


def test_unknown():

    description = """
    Strange vulnerability with no known family
    """

    result = classify_family(description)

    assert result == "unknown"