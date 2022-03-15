CPE = "cpe:/a:vmware:fusion";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810968" );
	script_version( "2021-09-09T11:01:33+0000" );
	script_cve_id( "CVE-2017-4902", "CVE-2017-4903", "CVE-2017-4904", "CVE-2017-4905" );
	script_bugtraq_id( 97163, 97160, 97165, 97164 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-09 11:01:33 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-12 01:29:00 +0000 (Wed, 12 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-07-03 15:15:42 +0530 (Mon, 03 Jul 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "VMware Fusion Code Execution And Information Disclosure Vulnerabilities (Mac OS X)" );
	script_tag( name: "summary", value: "The host is installed with VMware Fusion
  and is prone to information disclosure and multiple code execution
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - A heap buffer overflow and uninitialized stack memory usage in SVGA.

  - An uninitialized memory usage in XHCI controller." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  guest to execute code on the host and may also lead to information leak." );
	script_tag( name: "affected", value: "VMware Fusion 8.x before 8.5.6 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to VMware Fusion version 8.5.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.vmware.com/security/advisories/VMSA-2017-0006.html" );
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
	if(version_is_less( version: vmwareVer, test_version: "8.5.6" )){
		report = report_fixed_ver( installed_version: vmwareVer, fixed_version: "8.5.6" );
		security_message( data: report );
		exit( 0 );
	}
}

