if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801508" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)" );
	script_cve_id( "CVE-2010-3153" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Adobe InDesign Insecure Library Loading Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41126" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/14775/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_indesign_detect.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "insight", value: "The flaw is due to the application insecurely loading certain
libraries from the current working directory, which could allow attackers to
execute arbitrary code by tricking a user into opening a file from a network share." );
	script_tag( name: "solution", value: "Upgrade Adobe InDesign to version CS4 6.0.6 or later." );
	script_tag( name: "summary", value: "This host is installed with Adobe InDesign and is prone to insecure
library loading vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow the attackers to execute
arbitrary code and conduct DLL hijacking attacks." );
	script_tag( name: "affected", value: "Adobe InDesign version CS4 6.0" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
adVer = get_kb_item( "Adobe/InDesign/Ver" );
if(isnull( adVer )){
	exit( 0 );
}
adobeVer = eregmatch( pattern: " ([0-9.]+)", string: adVer );
if(!isnull( adobeVer[1] ) && ( ContainsString( adVer, "CS4" ) )){
	if(version_is_equal( version: adobeVer[1], test_version: "6.0" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

