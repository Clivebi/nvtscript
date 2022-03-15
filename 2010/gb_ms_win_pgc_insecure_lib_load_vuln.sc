if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801456" );
	script_version( "2019-12-20T12:48:41+0000" );
	script_tag( name: "last_modification", value: "2019-12-20 12:48:41 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2010-10-05 07:29:45 +0200 (Tue, 05 Oct 2010)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-3139" );
	script_name( "Microsoft Windows Progman Group Converter Insecure Library Loading Vulnerability" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/14758/" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/2200" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute
arbitrary code and conduct DLL hijacking attacks via a Trojan horse 'imm.dll'." );
	script_tag( name: "affected", value: "- Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 23 Service Pack 2 and prior

  - Microsoft Windows 2000 Service Pack 4 and prior" );
	script_tag( name: "insight", value: "The flaw is due to Windows Progman Group Converter (grpconv.exe)
which loads libraries in an insecure manner." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is installed Microsoft Windows Progman Group Converter
and is prone to insecure library loading vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("secpod_smb_func.inc.sc");
exit( 0 );
if(hotfix_check_sp( xp: 4, win2003: 3, win2k: 5 ) <= 0){
	exit( 0 );
}
sysPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\COM3\\Setup", item: "Install Path" );
if(!sysPath){
	exit( 0 );
}
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: sysPath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: sysPath + "\\grpconv.exe" );
exeSize = get_file_size( file: file, share: share );
if(exeSize != NULL){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

