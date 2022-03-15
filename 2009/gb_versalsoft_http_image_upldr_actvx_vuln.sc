if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800552" );
	script_version( "$Revision: 12602 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2009-04-17 09:00:01 +0200 (Fri, 17 Apr 2009)" );
	script_tag( name: "cvss_base", value: "8.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:C/A:C" );
	script_cve_id( "CVE-2008-6638" );
	script_bugtraq_id( 28301 );
	script_name( "Versalsoft HTTP Image Uploader ActiveX Vulnerability" );
	script_xref( name: "URL", value: "http://milw0rm.com/exploits/5569" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/41258" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Attacker may exploit this issue by deleting any arbitrary files on the
  remote system by tricking the user to visit a crafted malicious webpage." );
	script_tag( name: "affected", value: "Versalsoft HTTP Image Uploader 'UUploaderSvrD.dll' version 6.0.0.35 and
  prior." );
	script_tag( name: "insight", value: "Application has an insecure method 'RemoveFileOrDir()' declared in
  'UUploaderSvrD.dll' which allows the attacker to access, delete and
  corrupt system related files and folder contents." );
	script_tag( name: "summary", value: "This host is installed with Versalsoft HTTP Image Uploader
  and is prone to ActiveX vulnerability." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
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
imgupPath = registry_get_sz( key: "SOFTWARE\\Universal\\UImageUpoaderD", item: "InstallPath" );
if(!imgupPath){
	exit( 0 );
}
imgupPath = imgupPath + "\\UUploaderSvrD.dll";
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: imgupPath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: imgupPath );
imgupVer = GetVer( share: share, file: file );
if(imgupVer != NULL && version_is_less_equal( version: imgupVer, test_version: "6.0.0.35" )){
	if(is_killbit_set( clsid: "{04FD48E6-0712-4937-B09E-F3D285B11D82}" ) == 0){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

