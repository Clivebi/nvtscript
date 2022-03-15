CPE = "cpe:/a:ckeditor:ckeditor";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111095" );
	script_version( "2021-06-16T12:05:07+0000" );
	script_tag( name: "last_modification", value: "2021-06-16 12:05:07 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2016-04-17 18:00:00 +0200 (Sun, 17 Apr 2016)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_bugtraq_id( 69161 );
	script_name( "CKEditor < 4.4.3 Preview Plugin Unspecified XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_ckeditor_http_detect.sc" );
	script_mandatory_keys( "ckeditor/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/69161" );
	script_xref( name: "URL", value: "http://ckeditor.com/release/CKEditor-4.4.3" );
	script_tag( name: "summary", value: "The preview plugin for CKEditor is prone to an unspecified
  cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists because CKEditor fails to sufficiently sanitize
  user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This can allow
  the attacker to steal cookie-based authentication credentials and launch other attacks." );
	script_tag( name: "affected", value: "CKEditor prior to version 4.4.3." );
	script_tag( name: "solution", value: "Update version 4.4.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "4.4.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.4.3", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

