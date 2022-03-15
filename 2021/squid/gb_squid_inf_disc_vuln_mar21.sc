if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113797" );
	script_version( "2021-08-17T06:00:55+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 06:00:55 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-03-10 09:45:36 +0000 (Wed, 10 Mar 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-11 03:15:00 +0000 (Fri, 11 Jun 2021)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "NoneAvailable" );
	script_cve_id( "CVE-2021-28116" );
	script_name( "Squid <= 4.14, 5.x <= 5.0.5 Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_tag( name: "summary", value: "Squid is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability exists because of an out-of-bounds read
  in WCCP protocol data." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to
  read sensitive information." );
	script_tag( name: "affected", value: "Squid through version 4.14 and versions 5.0.0 through 5.0.5." );
	script_tag( name: "solution", value: "No known solution is available as of 10th March, 2021.
  Information regarding this issue will be updated once solution details are available." );
	script_xref( name: "URL", value: "https://www.zerodayinitiative.com/advisories/ZDI-21-157/" );
	exit( 0 );
}
CPE = "cpe:/a:squid-cache:squid";
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
if(version_is_less_equal( version: version, test_version: "4.14" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None Available", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.0.0", test_version2: "5.0.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None Available", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

