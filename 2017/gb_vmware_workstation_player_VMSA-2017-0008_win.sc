CPE = "cpe:/a:vmware:player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107208" );
	script_version( "2021-09-14T11:01:46+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 11:01:46 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-29 18:50:37 +0200 (Mon, 29 May 2017)" );
	script_cve_id( "CVE-2017-4912", "CVE-2017-4908", "CVE-2017-4909", "CVE-2017-4910", "CVE-2017-4911", "CVE-2017-4913", "CVE-2017-4900", "CVE-2017-4899", "CVE-2017-4898", "CVE-2017-4925" );
	script_bugtraq_id( 97921, 96771, 97920, 96770, 97916, 96772, 97913, 97912, 97911, 99997 );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-11 01:33:00 +0000 (Tue, 11 Jul 2017)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "VMware Workstation VMSA-2017-0008.2 Multiple Security Vulnerabilities (Windows)" );
	script_tag( name: "summary", value: "VMware Workstation updates resolve multiple
  security vulnerabilities (Windows)" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple heap
  buffer-overflow vulnerabilities in JPEG2000 and TrueType Font (TTF) parsers in
  the TPView.dll. Also there exists a DLL loading vulnerability that occurs due to
  the 'vmware-vmx' process loading DLLs from a path defined in the local
  environment-variable. Also a security vulnerability and a NULL pointer dereference
  vulnerability exists in the SVGA driver." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allows
  attackers to execute arbitrary code in the context of the affected application.
  Failed exploits will result in denial-of-service conditions. Also successful
  exploitation of this issue may allow normal users to escalate privileges to
  System in the host machine." );
	script_tag( name: "affected", value: "VMware Workstation 12.x versions prior to 12.5.3." );
	script_tag( name: "solution", value: "Update to Workstation 12.5.3." );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2017-0008.html" );
	script_xref( name: "URL", value: "https://www.vmware.com/security/advisories/VMSA-2017-0003.html" );
	script_xref( name: "URL", value: "https://www.vmware.com/security/advisories/VMSA-2017-0015.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_vmware_prdts_detect_win.sc" );
	script_mandatory_keys( "VMware/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!Ver = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( Ver, "^12\\." )){
	if(version_is_less( version: Ver, test_version: "12.5.3" )){
		report = report_fixed_ver( installed_version: Ver, fixed_version: "12.5.3" );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 99 );

