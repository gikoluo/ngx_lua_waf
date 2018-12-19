require 'config'
local match = string.match
local ngxmatch=ngx.re.match
local ngxfind=ngx.re.find
local unescape=ngx.unescape_uri
local get_headers = ngx.req.get_headers
local optionIsOn = function (options) return options == "on" and true or false end
logpath = logdir 
rulepath = RulePath
UrlDeny = optionIsOn(UrlDeny)
PostCheck = optionIsOn(postMatch)
CookieCheck = optionIsOn(cookieMatch)
WhiteCheck = optionIsOn(whiteModule)
PathInfoFix = optionIsOn(PathInfoFix)
attacklog = optionIsOn(attacklog)
CCDeny = optionIsOn(CCDeny)
HostCCDeny = optionIsOn(HostCCDeny)
HttpReferCCDeny = optionIsOn(HttpReferCCDeny)
Redirect=optionIsOn(Redirect)
local file = io.open('config.lua')

function getClientIp()
        IP  = ngx.var.remote_addr 
        if IP == nil then
                IP  = "unknown"
        end
        return IP
end

function write(logfile,msg)
    local fd = io.open(logfile,"ab")
    if fd == nil then return end
    fd:write(msg)
    fd:flush()
    fd:close()
end

function log(method,url,data,ruletag)
    if attacklog then
        local realIp = getClientIp()
        local ua = ngx.var.http_user_agent
        local servername=ngx.var.host
        local time=ngx.localtime()
        if ua  then
            line = realIp.." ["..time.."] \""..method.." "..servername.." - "..url.."\" \""..data.."\"  \""..ua.."\" \""..ruletag.."\"\n"
        else
            line = realIp.." ["..time.."] \""..method.." "..servername.." - "..url.."\" \""..data.."\" - \""..ruletag.."\"\n"
        end
        local filename = logpath..'/'..servername.."_"..ngx.today().."_sec.log"
        write(filename,line)
    end
end
------------------------------------规则读取函数-------------------------------------------------------------------
function read_rule(var)
    file = io.open(rulepath..var,"r")
    if file==nil then
        return
    end
    t = {}
    for line in file:lines() do
        table.insert(t,line)
    end
    file:close()
    return(t)
end

urlrules=read_rule('url')
argsrules=read_rule('args')
uarules=read_rule('user-agent')
wturlrules=read_rule('whiteurl')
postrules=read_rule('post')
ckrules=read_rule('cookie')
hostccdeny=read_rule('hostdenycc')

function say_html()
    if Redirect then
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(html)
        ngx.exit(ngx.status)
    end
end

function whiteurl()
    if WhiteCheck then
        if wturlrules ~=nil then
            for _,rule in pairs(wturlrules) do
                -- 针对完整 URL 白名单进行匹配
                if ngxfind(rule,"URL:","sjo") then
                    rule=string.gsub(rule,"URL:","",1)
                    if ngxfind(ngx.var.host..ngx.var.request_uri,rule,"isjo") then
                        -- log('whiteurl',ngx.var.request_uri,'-',rule)
                        return true
                    end
                elseif ngxfind(ngx.var.request_uri,rule,"isjo") then
                    -- log('whiteurl',ngx.var.request_uri,'-',rule)
                    return true 
                end
            end
        end
    end
    return false
end

function fileExtCheck(ext)
    local items = Set(black_fileExt)
    ext=string.lower(ext)
    if ext then
        for rule in pairs(items) do
            if ngxfind(ext,rule,"isjo") then
	        log('POST',ngx.var.request_uri,"-","file attack with ext "..ext)
            say_html()
            end
        end
    end
    return false
end
function Set (list)
  local set = {}
  for _, l in ipairs(list) do set[l] = true end
  return set
end

function args()
    for _,rule in pairs(argsrules) do
        local args = ngx.req.get_uri_args()
        for key, val in pairs(args) do
            if type(val)=='table' then
                 local t={}
                 for k,v in pairs(val) do
                    if v == true then
                        v=""
                    end
                    table.insert(t,v)
                end
                data=table.concat(t, " ")
            else
                data=val
            end
            if data and type(data) ~= "boolean" and rule ~="" and ngxfind(unescape(data),rule,"isjo") then
                log('GET',ngx.var.request_uri,"-",rule)
                say_html()
                return true
            end
        end
    end
    return false
end

function url()
    if UrlDeny then
        for _,rule in pairs(urlrules) do
            if rule ~="" and ngxfind(ngx.var.request_uri,rule,"isjo") then
                log('GET',ngx.var.request_uri,"-",rule)
                say_html()
                return true
            end
        end
    end
    return false
end

function ua()
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
        for _,rule in pairs(uarules) do
            if rule ~="" and ngxfind(ua,rule,"isjo") then
                log('UA',ngx.var.request_uri,"-",rule)
                say_html()
            return true
            end
        end
    end
    return false
end

function body(data)
    for _,rule in pairs(postrules) do
        if rule ~="" and data~="" and ngxfind(unescape(data),rule,"isjo") then
            log('POST',ngx.var.request_uri,data,rule)
            say_html()
            return true
        end
    end
    return false
end

function cookie()
    local ck = ngx.var.http_cookie
    if CookieCheck and ck then
        for _,rule in pairs(ckrules) do
            if rule ~="" and ngxfind(ck,rule,"isjo") then
                log('Cookie',ngx.var.request_uri,"-",rule)
                say_html()
            return true
            end
        end
    end
    return false
end

function denycc()
    if CCDeny then
        local uri=ngx.var.request_uri
        local host=ngx.var.host
        CCcount=tonumber(string.match(CCrate,'(.*)/'))
        CCseconds=tonumber(string.match(CCrate,'/(.*)'))
        local token = getClientIp()..host
        local limit = ngx.shared.limit
        local req,_=limit:get(token)
        if req then
            if req > CCcount then
                ngx.exit(503)
                return true
            elseif req == CCcount then
                limit:replace(token,req+1,600)
                log("CCDeny","-"," ban a ip ",'-')
                ngx.exit(503)
                return true
            else
                 limit:incr(token,1)
            end
        else
            local succ, err, forcible = limit:set(token,1,CCseconds)
            if not succ and err == "no memory" or forcible then
                ngx.log(ngx.WARN, "Fails to allocate memory for the current key-value item,consider raising the 'lua_shared_dict limit' memery. Now flush items")
                if limit:flush_expired() > 0 then
                    limit:set(token,1,CCseconds)
                end
            end
        end
    end
    return false
end

function httpReferDenycc()
    if HttpReferCCDeny then
        local uri=ngx.var.request_uri
        local host=ngx.var.host
        local httpRefer=ngx.var.http_referer
        if httpRefer == nil or httpRefer == "" then
            return false
        end
        local m, err = ngxmatch(HttpReferCCRate,"([0-9]+)/([0-9]+)/([0-9]+)")
        if m then
            CCcount=tonumber(m[1])
            CCseconds=tonumber(m[2])
            CCbanseconds=tonumber(m[3])

            local token = host..httpRefer
            local limit = ngx.shared.limit
            local req,_=limit:get(token)
            if req then
                if req > CCcount then
                    ngx.exit(503)
                    return true
                elseif req == CCcount then
                    limit:replace(token,req+1,CCbanseconds)
                    log("HttpReferCCDeny","-"," ban a http_refer ","rule: "..httpRefer)
                    ngx.exit(503)
                    return true
                else
                    limit:incr(token,1)
                end
            else
                local succ, err, forcible = limit:set(token,1,CCseconds)
                if not succ and err == "no memory" or forcible then
                    ngx.log(ngx.WARN, "Fails to allocate memory for the current key-value item,consider raising the 'lua_shared_dict limit' memery. Now flush items")
                    if limit:flush_expired() > 0 then
                        limit:set(token,1,CCseconds)
                    end
                end
            end
        end
    end
    return false
end

function hostDenyCC()
    if HostCCDeny then
        local uri=ngx.var.request_uri
        local host=ngx.var.host
        local remote_ip = getClientIp()
        if hostccdeny ~= nil then
            for _,rule in pairs(hostccdeny) do
                local m, err = ngxmatch(rule,"URL:([^ ]*) RATE:([0-9]+)/([0-9]+)/([0-9]+)")
                if m then
                    rule = m[1]
                    if ngxfind(host..uri,rule,"isjo") then
                        CCcount=tonumber(m[2])
                        CCseconds=tonumber(m[3])
                        CCbanseconds=tonumber(m[4])
                        local token = remote_ip..rule
                        local limit = ngx.shared.limit
                        local req,_=limit:get(token)
                        if req then
                            if req > CCcount then
                                ngx.exit(503)
                                return true
                            elseif req == CCcount then
                                limit:replace(token,req+1,CCbanseconds)
                                log("HOSDENYCC",uri," ban a ip: "..remote_ip,rule)
                                ngx.exit(503)
                                return true
                            else
                                limit:incr(token,1)
                            end
                        else
                            local succ, err, forcible = limit:set(token,1,CCseconds)
                            if not succ and err == "no memory" or forcible then
                                ngx.log(ngx.WARN, "Fails to allocate memory for the current key-value item,consider raising the 'lua_shared_dict limit' memery. Now flush items")
                                if limit:flush_expired() > 0 then
                                    limit:set(token,1,CCseconds)
                                end
                            end
                        end
                    end
                end
            end
        end
    end
    return false
end

function get_boundary()
    local header = get_headers()["content-type"]
    if not header then
        return nil
    end

    if type(header) == "table" then
        header = header[1]
    end

    local m = match(header, ";%s*boundary=\"([^\"]+)\"")
    if m then
        return m
    end

    return match(header, ";%s*boundary=([^\",;]+)")
end

function whiteip()
    if next(ipWhitelist) ~= nil then
        for _,ip in pairs(ipWhitelist) do
            if getClientIp()==ip then
                return true
            end
        end
    end
        return false
end

function blockip()
     if next(ipBlocklist) ~= nil then
         for _,ip in pairs(ipBlocklist) do
             if getClientIp()==ip then
                 ngx.exit(403)
                 return true
             end
         end
     end
         return false
end
