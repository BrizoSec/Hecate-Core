with open(".github/workflows/tests.yml", "r") as f:
    text = f.read()

replacement = """  validate-hunts:
    name: Validate Hunt Examples
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.11'
        cache: 'pip'

    - name: Set current month for STIX cache key
      id: date
      run: echo "month=$(date +'%Y-%m')" >> $GITHUB_OUTPUT

    - name: Cache STIX Data
      uses: actions/cache@v4
      with:
        path: ~/.hecate/stix-data
        key: stix-data-${{ steps.date.outputs.month }}

    - name: Install Hecate with ATT&CK support
      run: |
        python -m pip install --upgrade pip
        pip install -e ".[attack]"

    - name: Provision STIX data
      run: |
        hecate-agent attack update

    - name: Validate all hunts
      run: |
        hecate-agent hunt validate"""

text = text.replace("""  validate-hunts:
    name: Validate Hunt Examples
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.11'
        cache: 'pip'

    - name: Install Hecate
      run: |
        python -m pip install --upgrade pip
        pip install -e .

    - name: Validate all hunts
      run: |
        hecate-agent hunt validate""", replacement)

with open(".github/workflows/tests.yml", "w") as f:
    f.write(text)
