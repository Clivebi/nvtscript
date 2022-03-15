if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802372" );
	script_version( "$Revision: 11876 $" );
	script_cve_id( "CVE-2011-5032" );
	script_bugtraq_id( 51034 );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 14:20:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-01-06 11:24:26 +0530 (Fri, 06 Jan 2012)" );
	script_name( "WinMount 'WMDrive.sys' Driver IOCTL Handling Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/46872/" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/71764" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause the
application to crash." );
	script_tag( name: "affected", value: "WinMount version 3.5.1018 and prior." );
	script_tag( name: "insight", value: "The flaw is due to a null pointer dereference error in
WMDrive.sys, when processing a crafted '0x87342000 IOCTL' in the WMDriver
device." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with WinMount and is prone to denial of
service vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\WinMount_is1";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
wmountName = registry_get_sz( key: key, item: "DisplayName" );
if(ContainsString( wmountName, "WinMount" )){
	wmountVer = registry_get_sz( key: key, item: "DisplayVersion" );
	if(wmountVer != NULL){
		if(version_is_less_equal( version: wmountVer, test_version: "3.5.1018" )){
			sysPath = smb_get_systemroot();
			if(!sysPath){
				exit( 0 );
			}
			sysVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\WMDrive.sys" );
			if(!isnull( sysVer )){
				if(version_is_less_equal( version: sysVer, test_version: "3.4.181.224" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
}

