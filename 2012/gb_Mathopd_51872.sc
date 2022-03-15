if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103427" );
	script_bugtraq_id( 51872 );
	script_cve_id( "CVE-2012-1050" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_name( "Mathopd Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51872" );
	script_xref( name: "URL", value: "http://www.mathopd.org/" );
	script_xref( name: "URL", value: "http://www.mail-archive.com/mathopd%40mathopd.org/msg00392.html" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/521507" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2012-02-16 15:14:41 +0100 (Thu, 16 Feb 2012)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "Mathopd/banner" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "Mathopd is prone to a directory-traversal vulnerability because it
fails to sufficiently sanitize user-supplied input data." );
	script_tag( name: "impact", value: "Exploiting the issue may allow an attacker to obtain sensitive
information that could aid in further attacks." );
	script_tag( name: "affected", value: "Versions prior to Mathopd 1.5p7 are vulnerable." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: Mathopd/" )){
	exit( 0 );
}
version = eregmatch( pattern: "Server: Mathopd/([0-9.p]+)", string: banner );
vers = version[1];
if(!isnull( vers ) && !ContainsString( "unknown", vers )){
	if(ContainsString( vers, "p" )){
		vers1 = split( buffer: vers, sep: "p", keep: FALSE );
		if(!isnull( vers1[1] )){
			vers = vers1[0] + ".p" + vers1[1];
		}
	}
	if(version_is_less( version: vers, test_version: "1.5.p7" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

