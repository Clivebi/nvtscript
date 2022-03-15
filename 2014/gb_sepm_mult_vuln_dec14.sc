if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805203" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-3439", "CVE-2014-3438", "CVE-2014-3437" );
	script_bugtraq_id( 70843, 70844, 70845 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-12-04 09:43:28 +0530 (Thu, 04 Dec 2014)" );
	script_name( "Symantec Endpoint Protection Manager Multiple Vulnerabilities - Dec14" );
	script_tag( name: "summary", value: "This host is installed with Symantec
  Endpoint Protection Manager and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - The /console/Highlander_docs/SSO-Error.jsp script does not validate
    input to the 'ErrorMsg' parameter before returning it to users.

  - ConsoleServlet does not properly sanitize user input supplied via the
    'ActionType' parameter.

  - Incorrectly configured XML parser accepting XML external entities from an
    untrusted source.

  - The /portal/Loading.jsp script does not validate input to the 'uri' parameter
    before returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to gain access to arbitrary files, write to or overwrite arbitrary files and
  execute arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server." );
	script_tag( name: "affected", value: "Symantec Endpoint Protection Manager (SEPM)
  12.1 before RU5." );
	script_tag( name: "solution", value: "Upgrade to Symantec Endpoint Protection Manager
  12.1 RU5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1031176" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
http_port = http_get_port( default: 8443 );
res = http_get_cache( item: "/", port: http_port );
if(res && ContainsString( res, ">Symantec Endpoint Protection Manager<" ) && IsMatchRegexp( res, "&copy.*Symantec Coorporation<" )){
	url = "/console/Highlander_docs/SSO-Error.jsp?ErrorMsg=<script>alert(document" + ".cookie)</script>";
	req = http_get( item: url, port: http_port );
	res = http_keepalive_send_recv( port: http_port, data: req );
	if(IsMatchRegexp( res, "HTTP/1\\.. 200" ) && ContainsString( res, "<script>alert(document.cookie)</script>" ) && ContainsString( res, ">SSO Error<" )){
		security_message( port: http_port );
		exit( 0 );
	}
}
exit( 99 );

