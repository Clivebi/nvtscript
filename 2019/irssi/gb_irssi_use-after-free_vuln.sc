if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112481" );
	script_version( "2021-09-06T14:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-06 14:01:33 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-11 15:04:12 +0100 (Fri, 11 Jan 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-02-26 17:20:00 +0000 (Tue, 26 Feb 2019)" );
	script_cve_id( "CVE-2019-5882" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Irssi 1.1.x < 1.1.2 Use-After-Free Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_irssi_detect_lin.sc" );
	script_mandatory_keys( "irssi/detected" );
	script_tag( name: "summary", value: "Irssi is prone to a use-after-free vulnerability." );
	script_tag( name: "insight", value: "The vulnerability occurs when hidden lines were expired
  from the scroll buffer." );
	script_tag( name: "impact", value: "Exploiting this vulnerability may affect the stability of Irssi." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Irssi 1.1.x before 1.1.2." );
	script_tag( name: "solution", value: "Update to version 1.1.2." );
	script_xref( name: "URL", value: "https://irssi.org/security/irssi_sa_2019_01.txt" );
	script_xref( name: "URL", value: "https://github.com/irssi/irssi/pull/948" );
	script_xref( name: "URL", value: "https://irssi.org/NEWS/#v1-1-2" );
	exit( 0 );
}
CPE = "cpe:/a:irssi:irssi";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "1.1.0", test_version2: "1.1.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.1.2", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

