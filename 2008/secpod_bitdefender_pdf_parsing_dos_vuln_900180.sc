if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900180" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)" );
	script_cve_id( "CVE-2008-5409" );
	script_bugtraq_id( 32396 );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_family( "Denial of Service" );
	script_name( "BitDefender 'pdf.xmd' Module PDF Parsing Remote DoS Vulnerability" );
	script_xref( name: "URL", value: "http://milw0rm.com/exploits/7178" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/32789" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application and can deny the service to the legitimate user." );
	script_tag( name: "affected", value: "BitDefender Internet Security and Antivirus version 10 and prior on Windows" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Update to a later version." );
	script_tag( name: "summary", value: "This host is installed with BitDefender Internet Security and AntiVirus
  and is prone to denial of service vulnerability." );
	script_tag( name: "insight", value: "The flaw is due to boundary error in 'pdf.xmd' module when parsing of
  data encoded using 'FlateDecode' and 'ASCIIHexDecode' filters. This can be exploited to cause a memorycorruption during execution of 'bdc.exe'." );
	exit( 0 );
}
require("smb_nt.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
bitDef = "SOFTWARE\\BitDefender\\About\\";
bitName = registry_get_sz( key: bitDef, item: "ProductName" );
if(( ContainsString( bitName, "BitDefender Internet Security" ) ) || ( ContainsString( bitName, "BitDefender Antivirus" ) )){
	bitVer = registry_get_sz( key: bitDef, item: "ProductVersion" );
	if(egrep( pattern: "10(\\..*)", string: bitVer )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

