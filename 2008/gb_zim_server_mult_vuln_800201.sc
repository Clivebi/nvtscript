if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800201" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-12-03 15:02:49 +0100 (Wed, 03 Dec 2008)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-5279", "CVE-2008-5280" );
	script_bugtraq_id( 27940 );
	script_name( "ZIM Server Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://aluigi.altervista.org/adv/zilabzcsx-adv.txt" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/363848.php" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/29062" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation could result in remote arbitrary code execution and
  cause denial of service." );
	script_tag( name: "affected", value: "Zilab Software Zilab Chat and Instant Messaging Server 2.1 and prior." );
	script_tag( name: "insight", value: "The issues are due to:

  - boundary errors in the server while handling overly long crafted packets
  sent to default prot 7700.

  - a null pointer de-reference within the server will crash the service via
  a specially crafted packet sent to default port 7700." );
	script_tag( name: "solution", value: "Upgrde to Zilab Software Zilab Chat and Instant Messaging Server version 3.3 or later." );
	script_tag( name: "summary", value: "The host is installed with ZIM Server and is prone to multiple
  vulnerabilities." );
	script_xref( name: "URL", value: "http://www.zilab.com/zim.shtml" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
entries = registry_enum_keys( key: key );
for item in entries {
	ver = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( ver, "Zim" )){
		zimVer = eregmatch( pattern: "Zim v([0-9.]+)", string: ver );
		if(zimVer[1] != NULL){
			if(version_is_less_equal( version: zimVer[1], test_version: "2.1" )){
				report = report_fixed_ver( installed_version: zimVer[1], vulnerable_range: "Less than or equal to 2.1" );
				security_message( port: 0, data: report );
			}
		}
		exit( 0 );
	}
}

