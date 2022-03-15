CPE = "cpe:/a:phpbb:phpbb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100922" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-11-30 12:57:59 +0100 (Tue, 30 Nov 2010)" );
	script_bugtraq_id( 45005 );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_name( "phpBB 'includes/message_parser.php' HTML Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "phpbb_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpBB/installed" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/45005" );
	script_xref( name: "URL", value: "http://www.phpbb.com/support/documents.php?mode=changelog&version=3#v307-PL1" );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site. This may allow the attacker to steal cookie-based authentication
  credentials, control how the site is rendered to the user, or launch
  other attacks." );
	script_tag( name: "affected", value: "Versions prior to phpBB 3.0.8 are vulnerable." );
	script_tag( name: "solution", value: "The vendor has released updates. Please contact the vendor for
  details." );
	script_tag( name: "summary", value: "phpBB is prone to an HTML-injection vulnerability because it fails to
  properly sanitize user-supplied input." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "3.0.8" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.0.8" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

