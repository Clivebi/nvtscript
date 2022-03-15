if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800321" );
	script_version( "2019-07-24T08:39:52+0000" );
	script_tag( name: "last_modification", value: "2019-07-24 08:39:52 +0000 (Wed, 24 Jul 2019)" );
	script_tag( name: "creation_date", value: "2008-12-16 16:12:00 +0100 (Tue, 16 Dec 2008)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2008-5427" );
	script_name( "Norton Internet Security Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://mime.recurity.com/cgi-bin/twiki/view/Main/AttackIntro" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/499038/100/0/threaded" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/499045/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to deny the service." );
	script_tag( name: "affected", value: "Symantec, Norton AntiVirus version 15.5.0.23 on Windows." );
	script_tag( name: "insight", value: "The flaws are due to improper handling of multipart/mixed e-mail messages
  with many MIME parts and stack consumption by Content-type: message/rfc822
  headers via a large e-mail message." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host has Norton AntiVius in Norton Internet Security installed
  and is prone to Denial of Service Vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Symantec\\Internet Security" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	if(ContainsString( registry_get_sz( key: key + item, item: "DisplayName" ), "Norton AntiVirus" )){
		navVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(!navVer){
			exit( 0 );
		}
		if(IsMatchRegexp( navVer, "^15\\.5\\.0\\.23" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
}

