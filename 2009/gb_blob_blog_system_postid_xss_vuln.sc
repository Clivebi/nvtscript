if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800956" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-10-20 14:26:56 +0200 (Tue, 20 Oct 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-3594" );
	script_name( "BLOB Blog System 'postid' Parameter XSS Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35938/" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/51959" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_blob_blog_system_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "blog/blog-system/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "BLOB Blog System prior to 1.2 on all platforms." );
	script_tag( name: "insight", value: "This flaw is due to improper validation of user supplied data passed
  into the 'postid' parameter in the bpost.php." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to BLOB Blog System 1.2 or later." );
	script_tag( name: "summary", value: "This host is running BLOB Blog System and is prone to a Cross-Site
  Scripting vulnerability." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
bbsPort = http_get_port( default: 80 );
bbsVer = get_kb_item( "www/" + bbsPort + "/BLOB-Blog-System" );
bbsVer = eregmatch( pattern: "^(.+) under (/.*)$", string: bbsVer );
if(bbsVer[1] != NULL){
	if(version_is_less( version: bbsVer[1], test_version: "1.2" )){
		report = report_fixed_ver( installed_version: bbsVer[1], fixed_version: "1.2" );
		security_message( port: bbsPort, data: report );
		exit( 0 );
	}
}
exit( 99 );

