CPE = "cpe:/a:apache:couchdb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100572" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-04-12 18:40:45 +0200 (Mon, 12 Apr 2010)" );
	script_bugtraq_id( 39116 );
	script_cve_id( "CVE-2010-0009" );
	script_name( "CouchDB Message Digest Verification Security Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/39116" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_couchdb_detect.sc" );
	script_require_ports( "Services/www", 5984 );
	script_mandatory_keys( "couchdb/installed" );
	script_tag( name: "summary", value: "CouchDB is prone to a security-bypass vulnerability because it
compares message digests using a variable time algorithm." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allows an attacker to determine if
a forged digest is partially correct. Repeated attacks will allow them to determine specific, legitimate digests." );
	script_tag( name: "affected", value: "Versions prior to CouchDB 0.11 are vulnerable." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for
details." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "0.11" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.11" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

