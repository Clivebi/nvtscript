if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800086" );
	script_version( "$Revision: 12602 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2008-12-18 14:07:48 +0100 (Thu, 18 Dec 2008)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2008-5426" );
	script_name( "Kaspersky Internet Security Suite Malformed MIME Message DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation could result in application crash." );
	script_tag( name: "affected", value: "Kaspersky Internet Security Suite 2009 on Windows." );
	script_tag( name: "insight", value: "Flaw is due to improper handling of multipart/mixed e-mail messages
  with many MIME parts and e-mail messages with many Content-type: message/rfc822 headers." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to latest version of Kaspersky Internet Security Suite." );
	script_tag( name: "summary", value: "This host has Kaspersky Internet Security Suite installed and is
  prone to denial of service vulnerability." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
if(!( get_kb_item( "SMB/WindowsVersion" ) )){
	exit( 0 );
}
uninstall = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: uninstall )){
	exit( 0 );
}
for key in registry_enum_keys( key: uninstall ) {
	kisName = registry_get_sz( key: uninstall + key, item: "DisplayName" );
	if(ContainsString( kisName, "Kaspersky Internet Security" )){
		if(ContainsString( kisName, "Kaspersky Internet Security 2009" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
}

