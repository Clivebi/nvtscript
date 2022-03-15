if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105045" );
	script_cve_id( "CVE-2014-0224", "CVE-2014-0198", "CVE-2010-5298", "CVE-2014-3470" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_version( "2019-10-02T07:08:50+0000" );
	script_name( "VMSA-2014-0006: VMware product updates address OpenSSL security vulnerabilities (remote check)" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2014-0006.html" );
	script_tag( name: "last_modification", value: "2019-10-02 07:08:50 +0000 (Wed, 02 Oct 2019)" );
	script_tag( name: "creation_date", value: "2014-06-13 11:04:01 +0100 (Fri, 13 Jun 2014)" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_vmware_esx_web_detect.sc" );
	script_mandatory_keys( "VMware/ESX/build", "VMware/ESX/version" );
	script_tag( name: "vuldetect", value: "Check the build number" );
	script_tag( name: "insight", value: "a. OpenSSL update for multiple products.

OpenSSL libraries have been updated in multiple products to versions 0.9.8za and 1.0.1h
in order to resolve multiple security issues." );
	script_tag( name: "solution", value: "Apply the missing patch(es)." );
	script_tag( name: "summary", value: "VMware product updates address OpenSSL security vulnerabilities." );
	script_tag( name: "affected", value: "ESXi 5.5 prior to ESXi550-201406401-SGi,
ESXi 5.1 without patch ESXi510-201406401-SG,
ESXi 5.0 without patch ESXi500-201407401-SG" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("vmware_esx.inc.sc");
if(!esxVersion = get_kb_item( "VMware/ESX/version" )){
	exit( 0 );
}
if(!esxBuild = get_kb_item( "VMware/ESX/build" )){
	exit( 0 );
}
fixed_builds = make_array( "5.5.0", "1881737", "5.1.0", "1900470", "5.0.0", "1918656" );
if(!fixed_builds[esxVersion]){
	exit( 0 );
}
if(int( esxBuild ) < int( fixed_builds[esxVersion] )){
	security_message( port: 0, data: esxi_remote_report( ver: esxVersion, build: esxBuild, fixed_build: fixed_builds[esxVersion] ) );
	exit( 0 );
}
exit( 99 );

