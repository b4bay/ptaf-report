# Reporting tool for PT AF
This tools is designed to use with data produced by [ptaf-export](https://github.com/b4bay/ptaf-export) tool.
Report template should be created using [python-docx-template](https://docxtpl.readthedocs.io/en/latest/) syntax.

## Prerequisites
+ `python`
+ `pip`
    ```
    python3 -m pip install --user --upgrade pip
    ``` 
+ `virtualenv`

    On macOS and Linux:
    ```
    python3 -m pip install --user virtualenv
    ```
    On Windows:
    ```
    py -m pip install --user virtualenv
    ```
## Installation
1. Clone the project by git or extract zip with code
2. Create virtual environment in the project folder:

    On macOS and Linux:
    
    ```
    python3 -m venv env
    ```
    On Windows:
    ```
    py -m venv env
    ```
3. Activate virtual environment:

    On macOS and Linux:
    ```
    source env/bin/activate
    ```
    On Windows:
    ```
    .\env\Scripts\activate
    ```
4. Install dependencies

    ```
    pip install -r requirements.txt
    ``` 
## Usage
1. Activate virtual environment

    On macOS and Linux:
    ```
    source env/bin/activate
    ```
    On Windows:
    ```
    .\env\Scripts\activate
    ```
2. Copy data files produced by [ptaf-export](https://github.com/b4bay/ptaf-export) to the project folder.
3. Copy template file to the project folder.
4. Run `run.py`

    ```
    (venv) ubuntu@ubuntu:~/ptaf-report$ python3 ./run.py -h
    usage: run.py [-h] [-t TEMPLATE_FILE] [-o REPORT_FILE] [-m META_FILE] [-r RULES_FILE] [-p PROTECTORS_FILE]
                  [-e EVENTS_FILE] [--ua-csv-file UA_CSV]
    
    Build report with exported data from PT AF
    
    optional arguments:
    -h, --help          show this help message and exit
    -t TEMPLATE_FILE, --template TEMPLATE_FILE
                        template file name, template.docx by default
    -o REPORT_FILE, --output REPORT_FILE
                        report file name, report.docx by default
    -m META_FILE, --meta META_FILE
                        meta file name, meta.csv by default
    -r RULES_FILE, --rules RULES_FILE
                        rules file name, rules.csv by default
    -p PROTECTORS_FILE, --protectors PROTECTORS_FILE
                        protectors file name, protectors.csv by default
    -e EVENTS_FILE, --events EVENTS_FILE
                        events file name, events.csv by default
    --ua-csv-file UA_CSV  Filename to store UA stats (optional)
    ```

5. Deactivate virtual environment if needed

    ```
    deactivate
    ```

## Demo
1. Copy data files (`.csv`) and report template (`report.docx`) from `demo` folder to project folder:
2. Activate virtual environment
3. Run `run.py` with no parameters
    ```
    (venv) ubuntu@ubuntu:~/ptaf-report$ python3 ./run.py 
    [~] Starting to build report based on template.docx
    [+] Report saved to report.docx
    (venv) ubuntu@ubuntu:~/ptaf-report$ 
    ```
4. Open generated report from report.docx
