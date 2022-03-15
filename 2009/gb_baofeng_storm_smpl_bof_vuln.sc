if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800914" );
	script_version( "2020-04-27T09:00:11+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 09:00:11 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-08-05 14:14:14 +0200 (Wed, 05 Aug 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-2617" );
	script_bugtraq_id( 35512 );
	script_name( "BaoFeng Storm '.smpl' File Buffer Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_baofeng_storm_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Attacker may exploit this issue to execute arbitrary script code and may cause
  denial of service." );
	script_tag( name: "affected", value: "BaoFeng Storm version 3.09.62 and prior on Windows." );
	script_tag( name: "insight", value: "A boundary error occurs in the MediaLib.dll file while processing '.smpl'
  playlist file containing long pathname in the source attribute of ani item
  element." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to the latest BaoFeng Storm version 3.09.07.08." );
	script_tag( name: "summary", value: "This host is installed with BaoFeng Storm and is prone to
  Buffer Overflow vulnerability." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35592" );
	script_xref( name: "URL", value: "http://marc.info/?l=full-disclosure&m=124627617220913&w=2" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/fulldisclosure/2009-06/0287.html" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
stormVer = get_kb_item( "BaoFeng/Storm/Ver" );
if(!stormVer){
	exit( 0 );
}
stormPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\Uninstall\\Storm2", item: "DisplayIcon" );
if(!stormPath){
	exit( 0 );
}
stormPath = stormPath - "Storm.exe" + "MediaLib.dll";
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: stormPath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: stormPath );
stormdllVer = GetVer( share: share, file: file );
if(stormdllVer != NULL){
	if(version_is_less_equal( version: stormVer, test_version: "3.09.62" )){
		report = report_fixed_ver( installed_version: stormVer, vulnerable_range: "Less than or equal to 3.09.62", install_path: stormPath );
		security_message( port: 0, data: report );
	}
}

