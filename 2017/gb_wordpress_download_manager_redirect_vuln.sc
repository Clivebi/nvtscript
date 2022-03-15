if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106958" );
	script_version( "2021-09-10T12:01:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 12:01:36 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-18 10:05:48 +0700 (Tue, 18 Jul 2017)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-05 12:21:00 +0000 (Tue, 05 May 2020)" );
	script_cve_id( "CVE-2017-2217" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Download Manager Plugin Open Redirect Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/download-manager/detected" );
	script_tag( name: "summary", value: "Open redirect vulnerability in WordPress Download Manager allows remote
attackers to redirect users to arbitrary web sites and conduct phishing attacks via unspecified vectors." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Download Manager plugin 2.9.50 and prior." );
	script_tag( name: "solution", value: "Update to version 2.9.51 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/download-manager/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:w3_eden:download-manager";
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
if(version_is_less( version: version, test_version: "2.9.51" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.9.51", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

