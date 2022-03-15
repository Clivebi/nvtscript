CPE = "cpe:/a:horde:horde_groupware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143079" );
	script_version( "2021-08-30T08:01:20+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 08:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-10-30 06:53:22 +0000 (Wed, 30 Oct 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_cve_id( "CVE-2019-12094", "CVE-2019-12095" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Horde Groupware Webmail < 5.2.21 Multiple Vulnerabilities (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "horde_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "horde/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "Horde Groupware Webmail is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "Horde Groupware Webmail is prone to multiple vulnerabilities:

  - XSS vulnerability (CVE-2019-12094)

  - CSRF vulnerability in treanBookmarkTags parameter (CVE-2019-12095)" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Horde Groupware Webmail prior to version 5.2.21." );
	script_tag( name: "solution", value: "Update to version 5.2.21 or later." );
	script_xref( name: "URL", value: "https://bugs.horde.org/ticket/14926" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/46903" );
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
if(version_is_less( version: version, test_version: "5.2.21" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.2.21", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

