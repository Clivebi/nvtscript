if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15621" );
	script_version( "2020-06-04T07:59:52+0000" );
	script_tag( name: "last_modification", value: "2020-06-04 07:59:52 +0000 (Thu, 04 Jun 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_cve_id( "CVE-2001-1432" );
	script_bugtraq_id( 3772 );
	script_name( "Cherokee directory traversal flaw" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "gb_cherokee_http_detect.sc" );
	script_mandatory_keys( "cherokee/detected" );
	script_tag( name: "solution", value: "Upgrade to Cherokee 0.2.8 or newer." );
	script_tag( name: "summary", value: "The remote version of Cherokee is vulnerable to directory
  traversal flaw when appending a '../' sequence to the web request.

  Additionally, this version fails to drop root privileges after it binds
  to listen port." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Remote attacker can then submit specially crafted web request to
  browse any file on the server with root privileges." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
CPE = "cpe:/a:cherokee-project:cherokee";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "0.2.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.2.8", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

