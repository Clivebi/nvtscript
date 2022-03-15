CPE = "cpe:/a:vbulletin:vbulletin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143056" );
	script_version( "2021-09-02T13:01:30+0000" );
	script_tag( name: "last_modification", value: "2021-09-02 13:01:30 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-10-25 04:26:28 +0000 (Fri, 25 Oct 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-11 17:55:00 +0000 (Fri, 11 Oct 2019)" );
	script_cve_id( "CVE-2019-17131" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "vBulletin < 5.5.4 Clickjacking Vulnerability" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "vbulletin_detect.sc" );
	script_mandatory_keys( "vbulletin/detected" );
	script_tag( name: "summary", value: "vBulletin is prone to a clickjacking vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "vBulletin 5.5.3 and prior." );
	script_tag( name: "solution", value: "Update to 5.5.4 or later." );
	script_xref( name: "URL", value: "https://forum.vbulletin.com/forum/vbulletin-announcements/vbulletin-announcements_aa/4421373-vbulletin-connect-5-5-4-is-now-available-for-download" );
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
if(version_is_less( version: version, test_version: "5.5.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.5.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

