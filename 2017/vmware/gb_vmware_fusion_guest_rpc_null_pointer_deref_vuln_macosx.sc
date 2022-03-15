CPE = "cpe:/a:vmware:fusion";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811834" );
	script_version( "2021-09-13T14:16:31+0000" );
	script_cve_id( "CVE-2017-4925" );
	script_bugtraq_id( 100842 );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-13 14:16:31 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-29 16:01:00 +0000 (Fri, 29 Sep 2017)" );
	script_tag( name: "creation_date", value: "2017-09-20 17:13:25 +0530 (Wed, 20 Sep 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "VMware Fusion Guest RPC Null Pointer Dereference Vulnerability (Mac OS X)" );
	script_tag( name: "summary", value: "The host is installed with VMware Fusion
  and is prone to a NULL pointer dereference vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an error in handling
  guest RPC requests." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  with normal user privileges to crash their VMs." );
	script_tag( name: "affected", value: "VMware Fusion 8.x before 8.5.4 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to VMware Fusion version 8.5.4 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.vmware.com/security/advisories/VMSA-2017-0015.html" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "secpod_vmware_fusion_detect_macosx.sc" );
	script_mandatory_keys( "VMware/Fusion/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vmwareVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( vmwareVer, "^8\\." )){
	if(version_is_less( version: vmwareVer, test_version: "8.5.4" )){
		report = report_fixed_ver( installed_version: vmwareVer, fixed_version: "8.5.4" );
		security_message( data: report );
		exit( 0 );
	}
}

