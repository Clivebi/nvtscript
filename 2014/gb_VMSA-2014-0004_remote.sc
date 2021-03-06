if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105022" );
	script_cve_id( "CVE-2014-0076", "CVE-2014-0160" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_version( "$Revision: 12419 $" );
	script_name( "VMSA-2014-0004: VMware product updates address OpenSSL security vulnerabilities (remote check)" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-19 14:45:13 +0100 (Mon, 19 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2014-05-08 13:04:01 +0100 (Thu, 08 May 2014)" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_vmware_esx_web_detect.sc" );
	script_mandatory_keys( "VMware/ESX/build", "VMware/ESX/version" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2014-0004.html" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable build is present on the target host." );
	script_tag( name: "insight", value: "a. Information Disclosure vulnerability in OpenSSL third party library

  The OpenSSL library is updated to version openssl-1.0.1g to resolve multiple security issues." );
	script_tag( name: "solution", value: "Apply the missing patch(es)." );
	script_tag( name: "summary", value: "VMware product updates address OpenSSL security vulnerabilities." );
	script_tag( name: "affected", value: "ESXi 5.5 without patch ESXi550-201404020

  ESXi 5.5 Update 1 without patch ESXi550-201404001" );
	script_tag( name: "qod_type", value: "remote_banner" );
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
fixed_builds = make_array( "5.5.0", "1746974" );
if(!fixed_builds[esxVersion]){
	exit( 0 );
}
if(int( esxBuild ) < int( fixed_builds[esxVersion] )){
	security_message( port: 0, data: esxi_remote_report( ver: esxVersion, build: esxBuild, fixed_build: fixed_builds[esxVersion] ) );
	exit( 0 );
}
exit( 99 );

