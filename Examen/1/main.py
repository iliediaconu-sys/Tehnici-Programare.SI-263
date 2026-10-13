from checker import (
    SITES,
    build_url,
    is_https,
    show_response,
    check_site,
    scan_sites,
    check_headers,
    retry_check,
)

EXAMPLE = SITES[0]         
STATUS_200 = SITES[3]      
NOT_FOUND = SITES[6]      
SERVER_ERROR = SITES[7]    
NONEXISTENT = SITES[9]       
TWO_HEADERS = SITES[10]     
LOWERCASE_HEADER = SITES[11] 


# Partea 1
print("=== Partea 1: Funcții ===")
print("Partea 1, build_url fără /:", build_url("example.com", "login"))
print("Partea 1, build_url cu /:", build_url("example.com", "/login"))
print("Partea 1, is_https pe adresă https:", is_https(EXAMPLE))
print("Partea 1, is_https pe adresă http:", is_https(NONEXISTENT))

# Partea 2: apeluri pentru show response
print("\n=== Partea 2: Trimiterea unei cereri ===")
print("Partea 2, show_response pe", EXAMPLE)
show_response(EXAMPLE)
print("Partea 2, show_response pe", NONEXISTENT, "(site inexistent)")
show_response(NONEXISTENT)

# Partea 3: apeluri pentru check_site, pe fiecare adresă din SITES
print("\n=== Partea 3: Un verificator reutilizabil ===")
for url in SITES:
    print("Partea 3, check_site:", url, "->", check_site(url))

# Partea 4: apelu scan_sites()
print("\n=== Partea 4: Verificarea mai multor site-uri ===")
scan_sites()

# Partea 5: apeluri pentru check_headees
print("\n=== Partea 5: Audit de securitate ===")
print("Partea 5, check_headers cu 2 antete:", check_headers(TWO_HEADERS))
print("Partea 5, check_headers cu antet scris cu litere mici:", check_headers(LOWERCASE_HEADER))
print("Partea 5, check_headers pe pagină fără antete:", check_headers(STATUS_200))
print("Partea 5, check_headers pe site inaccesibil:", check_headers(NONEXISTENT))

# Partea 6: apeluri pentru retry_checck
print("\n=== Partea 6: Încercări repetate ===")
print("Partea 6, retry_check pe 200:", retry_check(STATUS_200))
print("Partea 6, retry_check pe 404:", retry_check(NOT_FOUND))
print("Partea 6, retry_check pe 500:", retry_check(SERVER_ERROR))
print("Partea 6, retry_check pe 500 cu attempts=2:", retry_check(SERVER_ERROR, attempts=2))
print("Partea 6, retry_check pe site inexistent:", retry_check(NONEXISTENT))
