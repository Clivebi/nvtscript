if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801440" );
	script_version( "$Revision: 12602 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2010-08-25 17:02:03 +0200 (Wed, 25 Aug 2010)" );
	script_bugtraq_id( 42525 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Adersoft VbsEdit '.vbs' File Denial Of Service Vulnerability" );
	script_xref( name: "URL", value: "http://inj3ct0r.com/exploits/13733" );
	script_xref( name: "URL", value: "http://www.expbase.com/Dos/12737.html" );
	script_xref( name: "URL", value: "http://www.0daynet.com/2010/0819/995.html" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/42525" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "insight", value: "The flaw exists due to an error in handling '.vbs' file which
  allows the user to crash the affected application." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with VbsEdit and is prone to Denial Of
  Service vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to crash the
  affected application, resulting in a denial-of-service condition." );
	script_tag( name: "affected", value: "Adersoft VbsEdit 4.6.1 and prior" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Adersoft\\Vbsedit" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Vbsedit";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
vbsName = registry_get_sz( key: key, item: "DisplayName" );
if(ContainsString( vbsName, "Vbsedit" )){
	vbsPath = registry_get_sz( key: key, item: "DisplayIcon" );
	if(!isnull( vbsPath )){
		vbsPath = vbsPath - ",0";
		share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: vbsPath );
		file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: vbsPath );
		vbsVer = GetVer( file: file, share: share );
		if(vbsVer != NULL){
			if(version_is_less_equal( version: vbsVer, test_version: "4.6.1" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
		}
	}
}

