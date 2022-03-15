CPE = "cpe:/a:sympa:sympa";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145041" );
	script_version( "2021-07-08T11:00:45+0000" );
	script_tag( name: "last_modification", value: "2021-07-08 11:00:45 +0000 (Thu, 08 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-12-15 05:23:58 +0000 (Tue, 15 Dec 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-13 04:15:00 +0000 (Wed, 13 Jan 2021)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-29668" );
	script_name( "Sympa < 6.2.60 SOAP API Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Privilege escalation" );
	script_dependencies( "sympa_detect.sc" );
	script_mandatory_keys( "sympa/detected" );
	script_tag( name: "summary", value: "Sympa is prone to an authentication bypass vulnerability in the
  SOAP API." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Sympa allows remote attackers to obtain full SOAP API access by
  sending any arbitrary string (except one from an expired cookie) as the cookie value to
  authenticateAndRun." );
	script_tag( name: "impact", value: "Successful exploitation may allow an unauthenticated attacker to
  execute arbitrary SOAP API calls." );
	script_tag( name: "affected", value: "Sympa version 6.2.58 and prior." );
	script_tag( name: "solution", value: "Update to version 6.2.60 or later." );
	script_xref( name: "URL", value: "https://github.com/sympa-community/sympa/issues/1041" );
	script_xref( name: "URL", value: "https://sympa-community.github.io/security/2020-003.html" );
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
if(version_is_less( version: version, test_version: "6.2.60" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.2.60", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

