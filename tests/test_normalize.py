from gangmu.normalize import strip_c_comments, tokenize


def test_comments_go_and_strings_stay():
    src = b'int a = 1; // trailing\n/* block */ char *s = "/* not a comment */";\n'
    out = strip_c_comments(src)
    assert b"trailing" not in out
    assert b"block" not in out
    assert b'"/* not a comment */"' in out


def test_formatting_does_not_change_the_token_stream():
    a = b"int add(int x, int y) {\n    return x + y;\n}\n"
    b = b"int add(int x,int y){return x+y;}"
    assert tokenize(a) == tokenize(b)


def test_identifiers_are_kept():
    assert b"tinynet_init" in tokenize(b"void tinynet_init(void);")


def test_numeric_suffixes_are_normalised():
    assert tokenize(b"x = 1u;") == tokenize(b"x = 1;")


def test_unterminated_block_comment_does_not_hang():
    assert tokenize(b"int a; /* never closed") == tokenize(b"int a;")


def test_hex_digits_are_not_mistaken_for_literal_suffixes():
    assert tokenize(b"0xFF") == [b"0xFF"]
    assert tokenize(b"0xFFu") == tokenize(b"0xFF")
    assert tokenize(b"0xABul") == tokenize(b"0xAB")
