CPE = "cpe:/a:kanboard:kanboard";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140302" );
	script_version( "2021-09-09T12:15:00+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 12:15:00 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-16 08:40:15 +0700 (Wed, 16 Aug 2017)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-24 15:51:00 +0000 (Thu, 24 Aug 2017)" );
	script_cve_id( "CVE-2017-12850", "CVE-2017-12851" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Kanboard Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_kanboard_detect.sc" );
	script_mandatory_keys( "kanboard/installed" );
	script_tag( name: "summary", value: "Kanboard is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Kanboard is prone to multiple vulnerabilities:

  - An authenticated standard user could reset the password of other users (including the admin) by altering form
data. (CVE-2017-12850)

  - An authenticated standard user could reset the password of the admin by altering form data. (CVE-2017-12851)" );
	script_tag( name: "affected", value: "Kanboard version 1.0.45 and prior." );
	script_tag( name: "solution", value: "Update to version 1.0.46 or later." );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2017/q3/297" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.0.46" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.0.46" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

