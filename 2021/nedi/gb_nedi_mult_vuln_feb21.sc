CPE = "cpe:/a:nedi:nedi";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145401" );
	script_version( "2021-08-27T08:01:04+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 08:01:04 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-02-17 04:23:23 +0000 (Wed, 17 Feb 2021)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-14 01:30:00 +0000 (Sun, 14 Feb 2021)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2021-26751", "CVE-2021-26752", "CVE-2021-26753" );
	script_name( "NeDi <= 1.9C, 2.0 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_nedi_detect.sc" );
	script_mandatory_keys( "nedi/detected" );
	script_tag( name: "summary", value: "NeDi is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - Authenticated SQL injection in the Monitoring History function (CVE-2021-26751)

  - Authenticated OS command execution (CVE-2021-26752)

  - Authenticated PHP code injection in the System Files function (CVE-2021-26753)" );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to access all the data in
  the database and obtain access to the NeDi application or obtain access to the operating system and all
  application data." );
	script_tag( name: "affected", value: "NeDi version 1.9C and probably prior and version 2.0." );
	script_tag( name: "solution", value: "Apply the provided patch." );
	script_xref( name: "URL", value: "https://n4nj0.github.io/advisories/nedi-multiple-vulnerabilities-i/" );
	script_xref( name: "URL", value: "https://forum.nedi.ch/index.php?topic=2322" );
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
if(version_is_less_equal( version: version, test_version: "1.9.100" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "Apply patch", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^2\\.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "Apply patch", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

