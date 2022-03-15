CPE = "cpe:/a:tenable:nessus";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813197" );
	script_version( "2021-09-29T12:07:39+0000" );
	script_cve_id( "CVE-2018-1147", "CVE-2018-1148" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-29 12:07:39 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-20 14:27:00 +0000 (Wed, 20 Jun 2018)" );
	script_tag( name: "creation_date", value: "2018-05-21 10:56:09 +0530 (Mon, 21 May 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Tenable Nessus Multiple Vulnerabilities (TNS-2018-05)" );
	script_tag( name: "summary", value: "Nessus is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to improper input
  validation and insufficient session management." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  authenticated attacker to execute arbitrary script code in a user's browser
  session and maintain system access even after a password change." );
	script_tag( name: "affected", value: "Nessus versions 7.0.3 and earlier." );
	script_tag( name: "solution", value: "Update to version 7.1.0 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.securitytracker.com/id/1040918" );
	script_xref( name: "URL", value: "https://www.tenable.com/security/tns-2018-05" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_nessus_web_server_detect.sc" );
	script_mandatory_keys( "nessus/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "7.1.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.1.0", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

