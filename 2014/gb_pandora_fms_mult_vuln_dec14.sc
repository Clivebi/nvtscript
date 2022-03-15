CPE = "cpe:/a:artica:pandora_fms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805204" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-12-04 12:25:10 +0530 (Thu, 04 Dec 2014)" );
	script_name( "Pandora FMS Multiple Vulnerabilities - Dec14" );
	script_tag( name: "summary", value: "This host is installed with Pandora FMS
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - The application installs with default user credentials.

  - An input passed to index.php script via the 'user' parameter is not
  properly sanitized before returning to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to gain privileged access, inject or manipulate SQL queries in the back-end
  database allowing for the manipulation or disclosure of arbitrary data." );
	script_tag( name: "affected", value: "Pandora FMS version 5.0 SP2 and prior." );
	script_tag( name: "solution", value: "Upgrade to Pandora FMS version 5.1 SP1 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/35380" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_pandora_fms_detect.sc" );
	script_mandatory_keys( "pandora_fms/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://pandorafms.com" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
url = "/pandora_console/mobile/index.php";
sndReq = http_get( port: http_port, item: url );
rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
input = eregmatch( pattern: "input([0-9a-z]+).*id", string: rcvRes );
if(!input[1]){
	exit( 0 );
}
postData = NASLString( "action=login&user=%27SQL-Injection-Test&password=test&input", input[1], "=Login" );
sndReq = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", get_host_name(), "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n\\r\\n", "\\r\\n", postData, "\\r\\n" );
rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
if(rcvRes && IsMatchRegexp( rcvRes, ">SQL error<.*SQL-Injection-Test" ) && ContainsString( rcvRes, ">Pandora FMS mobile<" )){
	security_message( http_port );
	exit( 0 );
}

