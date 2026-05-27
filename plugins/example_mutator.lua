-- Example Lua Mutate Plugin
-- This plugin generates variants of the input path

function mutate(original, ctx)
    local variants = {}
    
    -- Always include original
    table.insert(variants, original)
    
    -- Add uppercase version
    table.insert(variants, string.upper(original))
    
    -- Add lowercase version  
    table.insert(variants, string.lower(original))
    
    -- Add with common suffixes
    table.insert(variants, original .. ".bak")
    table.insert(variants, original .. ".old")
    table.insert(variants, original .. "~")
    
    -- Target-aware mutation (if engine passes target context)
    if ctx and ctx.target then
        if string.find(ctx.target, "%.php") then
            table.insert(variants, original .. ".php.bak")
        elseif string.find(ctx.target, "%.jsp") or string.find(ctx.target, "%.do") then
            table.insert(variants, original .. ".jsp.bak")
        end
    end
    
    return variants
end
