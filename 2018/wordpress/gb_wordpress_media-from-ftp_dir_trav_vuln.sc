if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112188" );
	script_version( "2021-05-27T06:00:15+0200" );
	script_tag( name: "last_modification", value: "2021-05-27 06:00:15 +0200 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2018-01-12 12:10:00 +0100 (Fri, 12 Jan 2018)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-29 12:38:00 +0000 (Mon, 29 Jan 2018)" );
	script_cve_id( "CVE-2018-5310" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Media From FTP Plugin Directory Traversal Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/media-from-ftp/detected" );
	script_tag( name: "summary", value: "Media From FTP plugin for WordPress is prone to a directory traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Media From FTP plugin before version 9.85." );
	script_tag( name: "solution", value: "Update to version 9.85 or later." );
	script_xref( name: "URL", value: "https://github.com/d4wner/Vulnerabilities-Report/blob/master/media-from-ftp.md" );
	exit( 0 );
}
CPE = "cpe:/a:riverforest-wp:media-from-ftp";
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
if(version_is_less( version: version, test_version: "9.85" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.85", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

