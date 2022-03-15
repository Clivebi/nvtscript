CPE = "cpe:/a:thewpninjas:ninja-forms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145242" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-01-22 09:00:54 +0000 (Fri, 22 Jan 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-08 19:45:00 +0000 (Fri, 08 Jan 2021)" );
	script_cve_id( "CVE-2020-36174", "CVE-2020-36175" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Ninja Forms Plugin < 3.4.27.1 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/ninja-forms/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Ninja Forms is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CSRF via services integration (CVE-2020-36174)

  - Validation bypass via the email field (CVE-2020-36175)" );
	script_tag( name: "affected", value: "WordPress Ninja Forms plugin version 3.4.27 and prior." );
	script_tag( name: "solution", value: "Update to version 3.4.27.1 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/ninja-forms/#developers" );
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
if(version_is_less( version: version, test_version: "3.4.27.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.4.27.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

