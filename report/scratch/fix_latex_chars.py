for path in ['report/chapters/04-implementation-analysis.md', 'report/chapters/07-security-and-safety-analysis.md']:
    with open(path, 'rb') as f:
        data = f.read()
    # Replace \x07 (bell) followed by 'lpha' with '\\alpha'
    data = data.replace(b'\x07lpha', b'\\alpha')
    # Replace \t (tab) followed by 'au' with '\\tau'
    data = data.replace(b'\tau', b'\\tau')
    # Replace \t (tab) followed by 'ext' with '\\text'
    data = data.replace(b'\text', b'\\text')
    # Replace \x0c (formfeed) with '\\f'
    data = data.replace(b'\x0csync', b'fsync')
    with open(path, 'wb') as f:
        f.write(data)
    print(f'Cleaned control characters in {path}')
