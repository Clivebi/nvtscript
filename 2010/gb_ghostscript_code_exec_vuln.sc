if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801269" );
	script_version( "2020-08-17T11:25:37+0000" );
	script_tag( name: "last_modification", value: "2020-08-17 11:25:37 +0000 (Mon, 17 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-09-08 14:19:28 +0200 (Wed, 08 Sep 2010)" );
	script_cve_id( "CVE-2009-3743" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Ghostscript Arbitrary Code Execution Vulnerability" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/644319" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/JALR-87YGN8" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_ghostscript_detect_win.sc" );
	script_mandatory_keys( "artifex/ghostscript/win/detected" );
	script_tag( name: "impact", value: "Successful exploitation allows the attackers to execute arbitrary code or
  cause a denial of service." );
	script_tag( name: "affected", value: "Ghostscript versions prior to 8.71" );
	script_tag( name: "insight", value: "The flaw is due to Off-by-one error in the TrueType bytecode
  interpreter in Ghostscript that allows remote attackers to execute arbitrary
  code or cause a denial of service (heap memory corruption) via a malformed
  TrueType font in a document." );
	script_tag( name: "solution", value: "Upgrade to Ghostscript version 8.71 or later." );
	script_tag( name: "summary", value: "This host is installed with Ghostscript and is prone to
  arbitrary code execution vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.ghostscript.com/" );
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
if(version_is_less( version: version, test_version: "8.71" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.71", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

