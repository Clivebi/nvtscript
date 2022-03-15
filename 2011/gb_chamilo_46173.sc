CPE = "cpe:/a:chamilo:chamilo_lms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103071" );
	script_version( "2021-08-11T09:43:36+0000" );
	script_tag( name: "last_modification", value: "2021-08-11 09:43:36 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2011-02-08 13:20:01 +0100 (Tue, 08 Feb 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Chamilo LMS <= 1.8.7.1 Multiple Remote File Disclosure Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_chamilo_http_detect.sc" );
	script_mandatory_keys( "chamilo/detected" );
	script_tag( name: "summary", value: "Chamilo is prone to multiple file-disclosure vulnerabilities
  because it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit these vulnerabilities to view local
  files in the context of the webserver process. This may aid in further attacks." );
	script_tag( name: "affected", value: "Chamilo version 1.8.7.1. Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/46173" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less_equal( version: version, test_version: "1.8.7.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

