if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140100" );
	script_cve_id( "CVE-2016-7463" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_version( "2019-12-18T11:13:08+0000" );
	script_name( "VMware ESXi updates address a cross-site scripting issue (VMSA-2016-0023)" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2016-0023.html" );
	script_tag( name: "vuldetect", value: "Checks if the target host is missing one or more patch(es)." );
	script_tag( name: "solution", value: "Apply the missing patch(es)." );
	script_tag( name: "summary", value: "The ESXi Host Client contains a vulnerability that may allow for stored cross-site scripting (XSS)." );
	script_tag( name: "insight", value: "The issue can be introduced by an attacker that has permission to manage virtual machines through ESXi
  Host Client or by tricking the vSphere administrator to import a specially crafted VM. The issue may be triggered on the system from
  where ESXi Host Client is used to manage the specially crafted VM." );
	script_tag( name: "last_modification", value: "2019-12-18 11:13:08 +0000 (Wed, 18 Dec 2019)" );
	script_tag( name: "creation_date", value: "2016-12-21 15:46:45 +0100 (Wed, 21 Dec 2016)" );
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
patches = make_array( "6.0.0", "VIB:esx-ui:1.9.0-4392584", "5.5.0", "VIB:esx-ui:1.12.0-4722375" );
if(!patches[esxVersion]){
	exit( 99 );
}
if(report = esxi_patch_missing( esxi_version: esxVersion, patch: patches[esxVersion] )){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

