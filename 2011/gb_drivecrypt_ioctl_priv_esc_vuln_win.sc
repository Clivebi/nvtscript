if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801799" );
	script_version( "$Revision: 11997 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)" );
	script_cve_id( "CVE-2011-0513" );
	script_bugtraq_id( 45750 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "SecurStar DriveCrypt 'DCR.sys' IOCTL Handling Privilege Escalation Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42881" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15972/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "insight", value: "The flaw exists due to an error in the 'DCR.sys' driver when processing 'IOCTLs'
  and can be exploited to corrupt memory via a specially crafted 0x00073800 IOCTL." );
	script_tag( name: "solution", value: "Upgrade to SecurStar DriveCrypt version 5.5 or later" );
	script_tag( name: "summary", value: "This host is installed with SecurStar DriveCrypt and is prone to
  privilege escalation vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary code." );
	script_tag( name: "affected", value: "SecurStar DriveCrypt version 5.3 and 5.4" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securstar.com/downloads.php" );
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
	drvName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( drvName, "DriveCrypt" )){
		drvVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(drvVer != NULL){
			if(version_is_equal( version: drvVer, test_version: "5.3" ) || version_is_equal( version: drvVer, test_version: "5.4" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
		}
	}
}

