if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105849" );
	script_cve_id( "CVE-2016-5331" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "2019-12-18T11:13:08+0000" );
	script_name( "VMware ESXi product updates address multiple important security issues (VMSA-2016-0010)" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2016-0010.html" );
	script_tag( name: "vuldetect", value: "Checks if the target host is missing one or more patch(es)." );
	script_tag( name: "solution", value: "Apply the missing patch(es)." );
	script_tag( name: "summary", value: "ESXi contain an HTTP header injection vulnerability due to lack of input validation." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to set arbitrary HTTP response headers and cookies,
  which may allow for cross-site scripting and malicious redirect attacks." );
	script_tag( name: "affected", value: "ESXi 6.0 without patch ESXi600-201603101-SG." );
	script_tag( name: "last_modification", value: "2019-12-18 11:13:08 +0000 (Wed, 18 Dec 2019)" );
	script_tag( name: "creation_date", value: "2016-08-05 16:10:53 +0200 (Fri, 05 Aug 2016)" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_family( "VMware Local Security Checks" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_vmware_esxi_init.sc" );
	script_mandatory_keys( "VMware/ESXi/LSC", "VMware/ESX/version" );
	exit( 0 );
}
require("vmware_esx.inc.sc");
require("version_func.inc.sc");
if(!get_kb_item( "VMware/ESXi/LSC" )){
	exit( 0 );
}
if(!esxVersion = get_kb_item( "VMware/ESX/version" )){
	exit( 0 );
}
patches = make_array( "6.0.0", "VIB:esx-base:6.0.0-1.31.3568943" );
if(!patches[esxVersion]){
	exit( 99 );
}
if(report = esxi_patch_missing( esxi_version: esxVersion, patch: patches[esxVersion] )){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

