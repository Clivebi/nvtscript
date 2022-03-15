CPE = "cpe:/a:vmware:workstation";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811265" );
	script_version( "2021-09-10T13:01:42+0000" );
	script_cve_id( "CVE-2017-4901" );
	script_bugtraq_id( 96881 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-10 13:01:42 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-12 01:29:00 +0000 (Wed, 12 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-08-01 17:03:57 +0530 (Tue, 01 Aug 2017)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "VMware Workstation Memory Corruption Vulnerability-VMSA-2017-0005 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with VMware Workstation
  and is prone to memory corruption vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to error in the
  drag-and-drop (DnD) function in VMware Workstation which has an out-of-bounds
  memory access vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow a guest
  to execute code on the operating system that runs Workstation." );
	script_tag( name: "affected", value: "VMware Workstation 12.x before 12.5.4 on
  Windows." );
	script_tag( name: "solution", value: "Upgrade to VMware Workstation version
  12.5.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.vmware.com/security/advisories/VMSA-2017-0005.html" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_vmware_prdts_detect_win.sc" );
	script_mandatory_keys( "VMware/Workstation/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vmwareVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( vmwareVer, "^12\\." )){
	if(version_is_less( version: vmwareVer, test_version: "12.5.4" )){
		report = report_fixed_ver( installed_version: vmwareVer, fixed_version: "12.5.4" );
		security_message( data: report );
		exit( 0 );
	}
}

