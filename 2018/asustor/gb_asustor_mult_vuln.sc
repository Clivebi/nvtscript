if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112365" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2018-08-28 10:11:00 +0200 (Tue, 28 Aug 2018)" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 13:56:00 +0000 (Tue, 30 Oct 2018)" );
	script_cve_id( "CVE-2018-15694", "CVE-2018-15695", "CVE-2018-15696", "CVE-2018-15697", "CVE-2018-15698", "CVE-2018-15699" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ASUSTOR Data Master < 3.1.6 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_asustor_adm_detect.sc" );
	script_mandatory_keys( "asustor_adm/detected" );
	script_tag( name: "summary", value: "ASUSTOR Data Master is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "ASUSTOR Data Master is prone to following vulnerabilities:

  - Authenticated File Upload (CVE-2018-15694)

  - Authenticated Arbitrary File Deletion (CVE-2018-15695)

  - Authenticated Account Enumeration (CVE-2018-15696)

  - Authenticated File Disclosure (CVE-2018-15697)

  - Authenticated File Disclosure (CVE-2018-15698)

  - MITM XSS (CVE-2018-15699)" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "ASUSTOR Data Master through version 3.1.5." );
	script_tag( name: "solution", value: "Update to version 3.1.6 or later." );
	script_xref( name: "URL", value: "https://www.tenable.com/security/research/tra-2018-22" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
CPE = "cpe:/h:asustor:adm_firmware";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
path = infos["location"];
if(version_is_less( version: version, test_version: "3.1.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.1.6", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

