if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105851" );
	script_cve_id( "CVE-2016-5330" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "2019-12-18T11:13:08+0000" );
	script_name( "VMware ESXi updates address multiple important security issues (VMSA-2016-0010)" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2016-0010.html" );
	script_tag( name: "vuldetect", value: "Checks if the target host is missing one or more patch(es)." );
	script_tag( name: "solution", value: "Apply the missing patch(es)." );
	script_tag( name: "summary", value: "A DLL hijacking vulnerability is present in the VMware Tools 'Shared Folders' (HGFS)
  feature running on Microsoft Windows." );
	script_tag( name: "impact", value: "Exploitation of this issue may lead to arbitrary code execution with the privileges
  of the victim. In order to exploit this issue, the attacker would need write access to a network share and they
  would need to entice the local user into opening their document.

  Successfully exploiting this issue requires installation of 'Shared Folders' component (HGFS feature) which does not
  get installed in 'custom/typical' installation of VMware Tools on Windows VM running on ESXi." );
	script_tag( name: "affected", value: "ESXi 6.0 without patch ESXi600-201603102-SG

  ESXi 5.5 without patch ESXi550-201607102-SG

  ESXi 5.1 without patch ESXi510-201605102-SG

  ESXi 5.0 without patch ESXi500-201606102-SG" );
	script_tag( name: "last_modification", value: "2019-12-18 11:13:08 +0000 (Wed, 18 Dec 2019)" );
	script_tag( name: "creation_date", value: "2016-08-05 16:10:53 +0200 (Fri, 05 Aug 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
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
patches = make_array( "6.0.0", "VIB:tools-light:6.0.0-1.31.3568943", "5.5.0", "VIB:tools-light:5.5.0-3.86.4179631", "5.1.0", "VIB:tools-light:5.1.0-3.82.3872638", "5.0.0", "VIB:tools-light:5.0.0-3.87.3982819" );
if(!patches[esxVersion]){
	exit( 99 );
}
if(report = esxi_patch_missing( esxi_version: esxVersion, patch: patches[esxVersion] )){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

