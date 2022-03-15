CPE = "cpe:/a:opencart:opencart";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145133" );
	script_version( "2021-08-17T14:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 14:01:00 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-01-13 09:30:44 +0000 (Wed, 13 Jan 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-30 16:43:00 +0000 (Wed, 30 Dec 2020)" );
	script_cve_id( "CVE-2020-29470", "CVE-2020-29471" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "NoneAvailable" );
	script_name( "OpenCart <= 3.0.3.7 Multiple XSS Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "opencart_detect.sc" );
	script_mandatory_keys( "OpenCart/installed" );
	script_tag( name: "summary", value: "OpenCart is prone to multiple cross-site scripting (XSS)
  vulnerabilities." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2020-29470: XSS in the Subject field of mail

  - CVE-2020-29471: XSS in the Profile Image" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "OpenCart version 3.0.3.7 and probably prior." );
	script_tag( name: "solution", value: "No known solution is available as of 15th July, 2021.
  Information regarding this issue will be updated once solution details are available." );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/49099" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/49098" );
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
if(version_is_less_equal( version: version, test_version: "3.0.3.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

