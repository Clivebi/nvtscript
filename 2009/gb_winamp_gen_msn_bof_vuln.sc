if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800531" );
	script_version( "$Revision: 12602 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2009-03-12 08:39:03 +0100 (Thu, 12 Mar 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-0833" );
	script_bugtraq_id( 33159 );
	script_name( "Winamp gen_msn.dll Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/33425" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/7696" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_winamp_detect.sc" );
	script_mandatory_keys( "Winamp/Version" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Attackers may leverage this issue by executing arbitrary code in the context
  of an affected application via specially crafted .pls files, and can cause
  buffer ovreflow." );
	script_tag( name: "affected", value: "Winamp version 5.541 and prior on Windows." );
	script_tag( name: "insight", value: "Boundary error exists in the player while processing overly long Winamp
  playlist entries in gen_msn.dll" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to Winamp version 5.572 or later" );
	script_tag( name: "summary", value: "This host has Winamp Player with gen_msn Plugin installed and
  is prone to buffer overflow vulnerability." );
	script_xref( name: "URL", value: "http://www.winamp.com/plugins" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
winampVer = get_kb_item( "Winamp/Version" );
if(!winampVer){
	exit( 0 );
}
if(version_is_less_equal( version: winampVer, test_version: "5.5.4.2165" )){
	winampPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows" + "\\CurrentVersion\\App Paths\\winamp.exe", item: "Path" );
	if(!winampPath){
		exit( 0 );
	}
	winampPath = winampPath + "\\Plugins\\gen_msn.dll";
	share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: winampPath );
	file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: winampPath );
	dllSize = get_file_size( share: share, file: file );
	if(dllSize != NULL && dllSize <= 45056){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

