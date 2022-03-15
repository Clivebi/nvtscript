if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100865" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-10-21 13:52:26 +0200 (Thu, 21 Oct 2010)" );
	script_bugtraq_id( 44264 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Atlassian FishEye Multiple Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/44264" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/62658" );
	script_xref( name: "URL", value: "http://www.atlassian.com/software/fisheye/" );
	script_xref( name: "URL", value: "http://confluence.atlassian.com/display/FISHEYE/FishEye+Security+Advisory+2010-10-20" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_FishEye_detect.sc" );
	script_require_ports( "Services/www", 8060 );
	script_mandatory_keys( "FishEye/installed" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Vendor updates are available. Please see the references for more
  information." );
	script_tag( name: "summary", value: "Atlassian FishEye is prone to multiple cross-site scripting
  vulnerabilities because it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage these issues to execute arbitrary HTML and
  script code in the browser of an unsuspecting user in the context of
  the affected site. This may let the attacker steal cookie-based
  authentication credentials and launch other attacks." );
	script_tag( name: "affected", value: "Versions prior to Atlassian FishEye 2.3.7 are vulnerable." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 8060 );
vers = get_kb_item( NASLString( "www/", port, "/FishEye" ) );
if(vers){
	if(version_is_less( version: vers, test_version: "2.3.7" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "2.3.7" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

