if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800050" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-11-05 13:21:04 +0100 (Wed, 05 Nov 2008)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-2992", "CVE-2008-2549", "CVE-2008-4812", "CVE-2008-4813", "CVE-2008-4817", "CVE-2008-4816", "CVE-2008-4814", "CVE-2008-4815" );
	script_bugtraq_id( 30035, 32100 );
	script_name( "Adobe Reader/Acrobat Multiple Vulnerabilities - Nov08 (Windows)" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb08-19.html" );
	script_xref( name: "URL", value: "http://www.coresecurity.com/content/adobe-reader-buffer-overflow" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to execute arbitrary code
  to cause a stack based overflow via a specially crafted PDF, and could
  also take complete control of the affected system and cause the application to crash." );
	script_tag( name: "insight", value: "The flaws are due to:

  - a boundary error when parsing format strings containing a floating point
    specifier in the util.printf() Javascript function.

  - improper parsing of type 1 fonts.

  - bounds checking not being performed after allocating an area of memory." );
	script_tag( name: "summary", value: "This host has Adobe Reader/Acrobat installed, which is/are prone
  to multiple vulnerabilities." );
	script_tag( name: "affected", value: "Adobe Reader versions 8.1.2 and prior - Windows(All)
  Adobe Acrobat Professional versions 8.1.2 and prior - Windows(All)" );
	script_tag( name: "solution", value: "Upgrade to 8.1.3 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
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
keys = registry_enum_keys( key: key );
for item in keys {
	adobeName = registry_get_sz( item: "DisplayName", key: key + item );
	if(ContainsString( adobeName, "Adobe Reader" ) || ContainsString( adobeName, "Adobe Acrobat" )){
		adobeVer = registry_get_sz( item: "DisplayVersion", key: key + item );
		if(!adobeVer){
			exit( 0 );
		}
		if(IsMatchRegexp( adobeVer, "^(7.*|8\\.0(\\..*)?|8\\.1(\\.[0-2])?)$" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
}

