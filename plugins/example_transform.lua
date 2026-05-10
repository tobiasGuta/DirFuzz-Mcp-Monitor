-- example_transform.lua
-- Demonstrates the transform_request(req) hook.
-- Adds a custom header and replaces dots in paths for WAF bypass.

function transform_request(req)
    -- Add a custom identification header
    req.headers["X-Custom-Tool"] = "DirFuzz"

    -- WAF bypass: replace dots with %2E URL encoding
    req.path = req.path:gsub("%.", "%%2E")

    return req
end
