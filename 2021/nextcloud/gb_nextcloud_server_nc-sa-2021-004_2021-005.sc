CPE = "cpe:/a:nextcloud:nextcloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145515" );
	script_version( "2021-08-26T06:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 06:01:00 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-03-08 03:55:49 +0000 (Mon, 08 Mar 2021)" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-09 09:15:00 +0000 (Fri, 09 Jul 2021)" );
	script_cve_id( "CVE-2021-22877", "CVE-2021-22878" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Nextcloud Server Multiple Vulnerabilities (NC-SA-2021-004, NC-SA-2021-005)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_nextcloud_detect.sc" );
	script_mandatory_keys( "nextcloud/installed" );
	script_tag( name: "summary", value: "Nextcloud Server is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - External storage credentials stored for wrong user (CVE-2021-22877)

  - Reflected XSS when renaming malicious file (CVE-2021-22878)" );
	script_tag( name: "affected", value: "Nextcloud server version 20.0.5 and prior." );
	script_tag( name: "solution", value: "Update to version 20.0.6 or later." );
	script_xref( name: "URL", value: "https://nextcloud.com/security/advisory/?id=NC-SA-2021-004" );
	script_xref( name: "URL", value: "https://nextcloud.com/security/advisory/?id=NC-SA-2021-005" );
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
if(version_is_less( version: version, test_version: "20.0.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "20.0.6", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

