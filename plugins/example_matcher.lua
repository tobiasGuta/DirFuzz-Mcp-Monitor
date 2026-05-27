-- Example Lua Match Plugin
-- This plugin matches responses containing valid JSON with a "success" field

function match(response)
    -- Access response fields:
    -- response.status_code (number)
    -- response.size (number)
    -- response.words (number)
    -- response.lines (number)
    -- response.body (string)
    -- response.content_type (string)
    
    local parsed, err = json_parse(response.body)
    if parsed and type(parsed) == "table" then
        if parsed.success == true then
            return true
        end
    end
    
    return false
end
