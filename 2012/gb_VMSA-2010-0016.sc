if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103449" );
	script_cve_id( "CVE-2010-0415", "CVE-2010-0307", "CVE-2010-0291", "CVE-2010-0622", "CVE-2010-1087", "CVE-2010-1437", "CVE-2010-1088", "CVE-2009-0844", "CVE-2009-0845", "CVE-2009-0846", "CVE-2009-4212", "CVE-2010-1321" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2019-12-18T11:13:08+0000" );
	script_name( "VMware ESXi/ESX third party updates for Service Console and Likewise components (VMSA-2010-0016)" );
	script_tag( name: "last_modification", value: "2019-12-18 11:13:08 +0000 (Wed, 18 Dec 2019)" );
	script_tag( name: "creation_date", value: "2012-03-15 16:13:01 +0100 (Thu, 15 Mar 2012)" );
	script_category( ACT_GATHER_INFO );
	script_family( "VMware Local Security Checks" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_vmware_esxi_init.sc" );
	script_mandatory_keys( "VMware/ESXi/LSC", "VMware/ESX/version" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2010-0016.html" );
	script_tag( name: "solution", value: "Apply the missing patch(es)." );
	script_tag( name: "vuldetect", value: "Checks if the target host is missing one or more patch(es)." );
	script_tag( name: "summary", value: "The remote ESXi is missing one or more security related Updates from VMSA-2010-0016." );
	script_tag( name: "affected", value: "VMware ESXi 4.1 without patch ESXi410-201010401-SG

  VMware ESX 4.1 without patches ESX410-201010401-SG, ESX410-201010419-SG

  VMware ESX 4.0 without patch ESX400-201101401-SG" );
	script_tag( name: "insight", value: "ESX Service Console OS (COS) kernel update, and Likewise packages
  updates resolve multiple security issues:

  a. Service Console OS update for COS kernel

  This patch updates the service console kernel to fix multiple
  security issues.

  b. Likewise package updates

  Updates to the likewisekrb5, likewiseopenldap, likewiseopen,
  and pamkrb5 packages address several security issues." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("vmware_esx.inc.sc");
if(!get_kb_item( "VMware/ESXi/LSC" )){
	exit( 0 );
}
if(!esxVersion = get_kb_item( "VMware/ESX/version" )){
	exit( 0 );
}
patches = make_array( "4.1.0", "ESXi410-201010401-SG" );
if(!patches[esxVersion]){
	exit( 99 );
}
if(report = esxi_patch_missing( esxi_version: esxVersion, patch: patches[esxVersion] )){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

