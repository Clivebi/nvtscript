if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900650" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-05-29 07:35:11 +0200 (Fri, 29 May 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-1643" );
	script_bugtraq_id( 34863 );
	script_name( "Sorinara Soritong MP3 Player Stack Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker craft a malicious
m3u playlist file and trick the user to open the application which will cause
stack overflow in the affected system and will crash the application." );
	script_tag( name: "affected", value: "Soritong MP3 Player version 1.0 and prior" );
	script_tag( name: "insight", value: "This flaw is due to an improper boundary checking when
processing '.m3u' files." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Sorinara Soritong MP3 Player and is prone
to Stack Overflow Vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/8624" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/50398" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\SoriTong\\";
appName = registry_get_sz( key: key, item: "DisplayName" );
if(ContainsString( appName, "SoriTong" )){
	readmePath = registry_get_sz( key: key, item: "UninstallString" );
	if(!readmePath){
		exit( 0 );
	}
	readmePath = readmePath - "\\uninstall.exe /uninstall";
	readmePath = readmePath + "\\Help";
	readmeText = smb_read_file( fullpath: readmePath + "\\whatsnew.html", offset: 0, count: 500 );
	if(!readmeText){
		exit( 0 );
	}
	saritongVer = eregmatch( pattern: "Version ([0-9.]+)", string: readmeText );
	if(saritongVer[1] != NULL){
		if(version_is_less_equal( version: saritongVer[1], test_version: "1.0" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}

