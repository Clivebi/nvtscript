if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900455" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-02-02 05:02:24 +0100 (Mon, 02 Feb 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-0298" );
	script_bugtraq_id( 33451 );
	script_name( "MW6 Technologies Barcode ActiveX Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/33663" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/7869" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker cause a heap buffer overflow
  via an overly long string assigned to the Supplement property." );
	script_tag( name: "insight", value: "ActiveX control in Barcode.dll due to a boundary error in the
  Barcode.MW6Barcode.1." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with MW6 Technologies Barcode ActiveX and
  is prone to Buffer Overflow Vulnerability." );
	script_tag( name: "affected", value: "Barcode ActiveX (Barcode.dll) version 3.0.0.1 and prior" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_activex.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Classes\\Barcode.MW6Barcode" )){
	exit( 0 );
}
sysPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\COM3\\Setup", item: "Install Path" );
if(!sysPath){
	exit( 0 );
}
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: sysPath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: sysPath + "\\Barcode.dll" );
dllVer = GetVer( file: file, share: share );
if(!dllVer){
	exit( 0 );
}
if(version_is_less_equal( version: dllVer, test_version: "3.0.0.1" )){
	if(!is_killbit_set( clsid: "{14D09688-CFA7-11D5-995A-005004CE563B}" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

