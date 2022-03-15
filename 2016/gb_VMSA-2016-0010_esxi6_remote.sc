if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105850" );
	script_cve_id( "CVE-2016-5331" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "$Revision: 13267 $" );
	script_name( "VMSA-2016-0010 (CVE-2016-5331) ESXi: VMware product updates address multiple important security issues (remote check)" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2016-0010.html" );
	script_tag( name: "vuldetect", value: "Check the build number." );
	script_tag( name: "solution", value: "Apply the missing patch(es)." );
	script_tag( name: "summary", value: "ESXi contain an HTTP header injection vulnerability due to lack of input validation. An attacker can exploit
  this issue to set arbitrary HTTP response headers and cookies, which may allow for cross-site scripting and malicious redirect attacks." );
	script_tag( name: "affected", value: "ESXi 6.0 without patch ESXi600-201603101-SG" );
	script_tag( name: "last_modification", value: "$Date: 2019-01-24 13:56:48 +0100 (Thu, 24 Jan 2019) $" );
	script_tag( name: "creation_date", value: "2016-08-05 16:16:34 +0200 (Fri, 05 Aug 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_vmware_esx_web_detect.sc" );
	script_mandatory_keys( "VMware/ESX/build", "VMware/ESX/version" );
	exit( 0 );
}
require("vmware_esx.inc.sc");
if(!esxVersion = get_kb_item( "VMware/ESX/version" )){
	exit( 0 );
}
if(!esxBuild = get_kb_item( "VMware/ESX/build" )){
	exit( 0 );
}
fixed_builds = make_array( "6.0.0", "3568943" );
if(!fixed_builds[esxVersion]){
	exit( 0 );
}
if(int( esxBuild ) < int( fixed_builds[esxVersion] )){
	security_message( port: 0, data: esxi_remote_report( ver: esxVersion, build: esxBuild, fixed_build: fixed_builds[esxVersion] ) );
	exit( 0 );
}
exit( 99 );

