if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801882" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-05-18 15:37:30 +0200 (Wed, 18 May 2011)" );
	script_bugtraq_id( 47402 );
	script_cve_id( "CVE-2011-1589" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Mojolicious Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/44051" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/66830" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=697229" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc", "os_detection.sc" );
	script_mandatory_keys( "Mojolicious/banner" );
	script_require_ports( "Services/www", 3000 );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks." );
	script_tag( name: "affected", value: "Mojolicious versions prior to 1.16." );
	script_tag( name: "insight", value: "The flaw is due to an error in 'Path.pm', which allows remote
  attackers to read arbitrary files via a %2f..%2f (encoded slash dot dot slash) in a URI." );
	script_tag( name: "solution", value: "Upgrade to Mojolicious version 1.16 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The host is running Mojolicious and is prone to directory traversal
  vulnerability." );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 3000 );
banner = http_get_remote_headers( port: port );
if(ContainsString( banner, "Server: Mojolicious" )){
	files = traversal_files();
	for file in keys( files ) {
		url = NASLString( crap( data: "..%2f", length: 5 * 10 ), files[file] );
		if(http_vuln_check( port: port, url: url, pattern: file )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
		}
	}
}

