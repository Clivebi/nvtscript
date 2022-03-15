if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803889" );
	script_version( "2020-05-14T13:01:46+0000" );
	script_cve_id( "CVE-2012-4351" );
	script_bugtraq_id( 57170 );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-05-14 13:01:46 +0000 (Thu, 14 May 2020)" );
	script_tag( name: "creation_date", value: "2013-09-06 17:12:34 +0530 (Fri, 06 Sep 2013)" );
	script_name( "Symantec PGP Desktop and Encryption Desktop Integer Overflow Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with Symantec PGP/Encryption Desktop and is prone to
  integer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to version 10.3.0 MP1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "insight", value: "Flaw is due to an unspecified error in pgpwded.sys." );
	script_tag( name: "affected", value: "Symantec PGP Desktop 10.0.x, 10.1.x, and 10.2.x
  Symantec Encryption Desktop 10.3.0 prior to 10.3.0 MP1." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote unauthenticated attacker to execute
  arbitrary code and or gain escalated privileges." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51762" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/52219" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_family( "General" );
	script_dependencies( "gb_pgp_desktop_detect_win.sc" );
	script_mandatory_keys( "PGPDesktop_or_EncryptionDesktop/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:symantec:pgp_desktop",
	 "cpe:/a:symantec:encryption_desktop" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "10.0", test_version2: "10.3.0.9059" )){
	report = report_fixed_ver( installed_version: vers, vulnerable_range: "10.0 - 10.3.0.9059", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

