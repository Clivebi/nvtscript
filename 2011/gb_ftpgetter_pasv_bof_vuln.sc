if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801839" );
	script_version( "$Revision: 11997 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)" );
	script_bugtraq_id( 46120 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "FTPGetter 'PASV' Command Remote Stack Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "https://secunia.com/advisories/41857" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/16101/" );
	script_xref( name: "URL", value: "http://downloads.securityfocus.com/vulnerabilities/exploits/46120.py" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "insight", value: "The flaw is due to a boundary error when reading a log file
using fgets() which can be exploited to cause a stack-based buffer overflow
by tricking a user into connecting to a malicious FTP server and sending a
specially crafted 'PWD' or 'PASV' response." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with FTPGetter FTP Client and is prone to
buffer overflow vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation allows execution of arbitrary code." );
	script_tag( name: "affected", value: "FTPGetter version 3.58.0.21 and prior." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	fgName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( fgName, "FTPGetter" )){
		fgpath = registry_get_sz( key: key + item, item: "DisplayIcon" );
		if(!isnull( fgpath )){
			share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: fgpath );
			file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: fgpath );
			fgVer = GetVer( file: file, share: share );
			if(fgVer != NULL){
				if(version_is_less_equal( version: fgVer, test_version: "3.58.0.21" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
}

