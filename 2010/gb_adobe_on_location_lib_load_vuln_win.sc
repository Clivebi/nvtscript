if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801511" );
	script_version( "$Revision: 12602 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)" );
	script_cve_id( "CVE-2010-3151" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Adobe On Location Insecure Library Loading Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/14772/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/513332/2010-08-20/2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "insight", value: "The flaw is due to the application insecurely loading certain
libraries from the current working directory, which could allow attackers to
execute arbitrary code by tricking a user into opening a file from a network share." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Adobe On Location and is prone to
insecure library loading vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary
code and conduct DLL hijacking attacks." );
	script_tag( name: "affected", value: "Adobe On Location CS4 Build 315 on windows." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Adobe" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	adName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( adName, "Adobe OnLocation CS4" )){
		adVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(!isnull( adVer )){
			if(version_is_equal( version: adVer, test_version: "4.0.315" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

