CPE = "cpe:/a:vmware:fusion";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810530" );
	script_version( "2021-09-14T08:01:37+0000" );
	script_cve_id( "CVE-2016-7461" );
	script_bugtraq_id( 94280 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-14 08:01:37 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-28 01:29:00 +0000 (Fri, 28 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-02-03 13:26:09 +0530 (Fri, 03 Feb 2017)" );
	script_name( "VMware Fusion DnD Function Out-of-Bounds Memory Access Vulnerability (Mac OS X)" );
	script_tag( name: "summary", value: "The host is installed with VMware Fusion
  and is prone to an out-of-bounds memory access vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an out-of-bounds memory
  access error in drag-and-drop (DnD) function." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to execute arbitrary code in the context of the user running the
  affected application. Failed exploit attempts will likely result in
  denial-of-service conditions." );
	script_tag( name: "affected", value: "VMware Fusion 8.x before 8.5.2 on
  Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to VMware Fusion version
  8.5.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2016-0019.html" );
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
if(IsMatchRegexp( vmwareVer, "^8" )){
	if(version_is_less( version: vmwareVer, test_version: "8.5.2" )){
		report = report_fixed_ver( installed_version: vmwareVer, fixed_version: "8.5.2" );
		security_message( data: report );
		exit( 0 );
	}
}

