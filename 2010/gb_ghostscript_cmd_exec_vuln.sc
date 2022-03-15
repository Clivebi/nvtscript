if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801412" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)" );
	script_cve_id( "CVE-2010-2055" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Ghostscript Arbitrary Command Execution Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_ghostscript_detect_win.sc" );
	script_mandatory_keys( "artifex/ghostscript/win/detected" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40452" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/1757" );
	script_xref( name: "URL", value: "http://www.ghostscript.com" );
	script_tag( name: "impact", value: "Successful exploitation allows the attackers to execute arbitrary
  postscript commands via the 'gs_init.ps' file, if a user is tricked into opening
  a file using the '-P-' option in an attacker controlled directory." );
	script_tag( name: "affected", value: "Ghostscript version 8.71 and prior" );
	script_tag( name: "insight", value: "The flaw is due to: application reading certain postscript files
  in the current working directory although the '-P-' command line option is set." );
	script_tag( name: "solution", value: "Upgrade Ghostscript to version 9.0 or later." );
	script_tag( name: "summary", value: "This host is installed with Ghostscript and is prone to
  arbitrary command execution vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
CPE = "cpe:/a:artifex:ghostscript";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "9.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.0", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

