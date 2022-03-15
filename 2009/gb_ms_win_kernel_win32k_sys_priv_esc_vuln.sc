if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800862" );
	script_version( "2019-12-20T10:24:46+0000" );
	script_tag( name: "last_modification", value: "2019-12-20 10:24:46 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2009-08-11 07:36:16 +0200 (Tue, 11 Aug 2009)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-2653" );
	script_name( "Microsoft Windows Kernel win32k.sys Privilege Escalation Vulnerability" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9301" );
	script_xref( name: "URL", value: "http://www.ntinternals.org/index.html#09_07_30" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2009/Jul/1022630.html" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Privilege escalation" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation could allow local administrators to
  bypass unspecified 'security software' and gain privileges." );
	script_tag( name: "affected", value: "- Microsoft Windows XP SP2/SP3 and prior

  - Microsoft Windows Server 2003 before SP1" );
	script_tag( name: "insight", value: "The flaw is due to error in NtUserConsoleControl function in
  win32k.sys caused via a crafted call that triggers an overwrite of an arbitrary memory location." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "Windows XP/2003 is prone to Privilege Escalation vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
winVer = get_kb_item( "SMB/WindowsVersion" );
if(IsMatchRegexp( winVer, "^5\\.[12]" )){
	SP = get_kb_item( "SMB/WinXP/ServicePack" );
	SvPk = get_kb_item( "SMB/Win2003/ServicePack" );
	if(( ContainsString( SP, "Service Pack 2" ) ) || ( ContainsString( SP, "Service Pack 3" ) ) || isnull( SvPk )){
		sysPath = registry_get_sz( item: "Install Path", key: "SOFTWARE\\Microsoft\\COM3\\Setup" );
		sysPath += "\\win32k.sys";
		share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: sysPath );
		file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: sysPath );
		sysVer = GetVer( file: file, share: share );
		if( IsMatchRegexp( sysVer, "^5\\.1\\." ) ){
			if(version_is_less_equal( version: sysVer, test_version: "5.1.2600.5796" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
		}
		else {
			if(IsMatchRegexp( sysVer, "^5\\.2\\." )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
		}
	}
}

