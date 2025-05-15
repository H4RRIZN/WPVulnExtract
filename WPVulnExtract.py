#!/usr/bin/python3
import re
import sys
import pandas as pd
from prettytable import PrettyTable

# Made by H4RRIZN

def procesar_wpscan(archivo):
    table = PrettyTable()
    table.field_names = ["Plugin", "Tipo", "CVE"]
    
    data = []

    try:
        with open(archivo, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"El archivo '{archivo}' no se encuentra.")
        return

    plugin_name = ""
    vulnerability_type = ""
    cve_list = []

    for line in lines:
        line = line.strip()
        line = line.lstrip('|').strip()
        
        match_title = re.match(r"^\[!\] Title:\s*(.*?)\s*-\s*(.*)", line)
        if match_title:
            if plugin_name:
                table.add_row([plugin_name, vulnerability_type, ", ".join(cve_list)])
                data.append([plugin_name, vulnerability_type, ", ".join(cve_list)])

            plugin_name = match_title.group(1)
            vulnerability_type = match_title.group(2)
            cve_list = []

        match_cve = re.findall(r"CVE-\d{4}-\d{4,7}", line)
        for cve in match_cve:
            if cve not in cve_list:
                cve_list.append(cve)

    if plugin_name and cve_list:
        table.add_row([plugin_name, vulnerability_type, ", ".join(cve_list)])
        data.append([plugin_name, vulnerability_type, ", ".join(cve_list)])

    print(table)

    df = pd.DataFrame(data, columns=["Plugin", "Tipo", "CVE"])
    excel_filename = archivo.split('.')[0] + "_vulnerabilidades.xlsx"
    df.to_excel(excel_filename, index=False)

    print(f"\nEl archivo Excel ha sido generado: {excel_filename}")

if len(sys.argv) != 2:
    print("Por favor, proporciona el archivo de salida de wpscan como argumento.")
    sys.exit(1)

archivo = sys.argv[1]

procesar_wpscan(archivo)
