if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900552" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-06-04 10:49:28 +0200 (Thu, 04 Jun 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-1831" );
	script_bugtraq_id( 35052 );
	script_name( "Winamp gen_ff.dll Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://vrt-sourcefire.blogspot.com/2009/05/winamp-maki-parsing-vulnerability.html" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_winamp_detect.sc" );
	script_mandatory_keys( "Winamp/Version" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Attackers may leverage this issue by executing arbitrary codes in the
  context of the affected application via specially crafted .maki files and can cause denial of service." );
	script_tag( name: "affected", value: "Winamp version 5.55 and prior on Windows." );
	script_tag( name: "insight", value: "The vulnerability exists in the gen_ff.dll file which is prone to integer
  overflow due to an incorrect type cast error while processing malicious .maki file." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to the version 5.552." );
	script_tag( name: "summary", value: "This host is installed with Winamp and is prone to Buffer
  Overflow vulnerability." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
winampVer = get_kb_item( "Winamp/Version" );
if(!winampVer){
	exit( 0 );
}
if(version_is_less_equal( version: winampVer, test_version: "5.5.5.2405" )){
	winPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\App Paths\\winamp.exe", item: "Path" );
	if(!winPath){
		exit( 0 );
	}
	winPath = winPath + "\\Plugins\\gen_ff.dll";
	share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: winPath );
	file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: winPath );
	dllSize = get_file_size( share: share, file: file );
	if(dllSize){
		report = report_fixed_ver( installed_version: winampVer, vulnerable_range: "Less than or equal to 5.5.5.2405", install_path: winPath );
		security_message( port: 0, data: report );
	}
}

