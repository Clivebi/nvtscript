if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112326" );
	script_version( "2021-05-27T06:00:15+0200" );
	script_tag( name: "last_modification", value: "2021-05-27 06:00:15 +0200 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2018-07-16 11:20:14 +0200 (Mon, 16 Jul 2018)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:19:00 +0000 (Wed, 09 Oct 2019)" );
	script_cve_id( "CVE-2016-6565" );
	script_bugtraq_id( 94356 );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress NextGEN Gallery Plugin < 2.1.57 Local File Inclusion Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/nextgen-gallery/detected" );
	script_tag( name: "summary", value: "The Imagely NextGen Gallery plugin for WordPress may execute code from an uploaded malicious file." );
	script_tag( name: "insight", value: "The Imagely NextGen Gallery plugin for WordPress does not properly validate user input in the cssfile
  parameter of a HTTP POST request, which may allow an authenticated user to read arbitrary files from the server,
  or execute arbitrary code on the server in some circumstances (dependent on server configuration)." );
	script_tag( name: "impact", value: "An authenticated user may be able to read arbitrary files on the server
  or execute code on the server by including a malicious local file in a formatted server request." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress NextGEN Gallery plugin before 2.1.57." );
	script_tag( name: "solution", value: "Update to version 2.1.57 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/nextgen-gallery/#developers" );
	script_xref( name: "URL", value: "https://www.kb.cert.org/vuls/id/346175" );
	exit( 0 );
}
CPE = "cpe:/a:imagely:nextgen-gallery";
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
if(version_is_less( version: version, test_version: "2.1.57" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.1.57", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

