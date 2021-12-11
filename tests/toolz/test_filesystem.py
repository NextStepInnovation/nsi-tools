from nsi.toolz import pipe, slurplines

def test_slurplines(multiline_path):
    assert pipe(
        multiline_path,
        slurplines,
        tuple,
    ) == ('a,b,c', '1,2,3')


    