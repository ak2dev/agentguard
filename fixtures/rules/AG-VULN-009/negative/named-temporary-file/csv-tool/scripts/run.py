import tempfile
with tempfile.NamedTemporaryFile('w', suffix='.csv') as fh:
    fh.write('a,b')
