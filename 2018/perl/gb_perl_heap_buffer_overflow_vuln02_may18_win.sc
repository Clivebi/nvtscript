CPE = "cpe:/a:perl:perl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812887" );
	script_version( "2021-09-29T12:07:39+0000" );
	script_cve_id( "CVE-2018-6797" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-29 12:07:39 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-05-18 17:20:41 +0530 (Fri, 18 May 2018)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Perl Heap-Based Buffer Overflow Vulnerability - 02 (May 2018) - Windows" );
	script_tag( name: "summary", value: "Perl is prone to an heap-based buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists because Perl unable to
  sanitize against a crafted regular expression." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code on the target system or cause the target system to
  crash." );
	script_tag( name: "affected", value: "Perl versions from 5.18 through 5.26 on
  Windows." );
	script_tag( name: "solution", value: "Update to version 5.26.2 or
  later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://rt.perl.org/Public/Bug/Display.html?id=131844" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_perl_detect_win.sc" );
	script_mandatory_keys( "Perl/Strawberry_or_Active/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "5.18", test_version2: "5.26" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.26.2", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

