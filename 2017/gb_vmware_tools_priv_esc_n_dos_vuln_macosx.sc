CPE = "cpe:/a:vmware:tools";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810266" );
	script_version( "2021-09-15T11:15:39+0000" );
	script_cve_id( "CVE-2016-7079", "CVE-2016-7080" );
	script_bugtraq_id( 92938 );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-15 11:15:39 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-30 01:29:00 +0000 (Sun, 30 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-01-10 12:53:05 +0530 (Tue, 10 Jan 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "VMware Tools Privilege Escalation And Denial Of Service Vulnerabilities (Mac OS X)" );
	script_tag( name: "summary", value: "The host is installed with VMware Tools
  and is prone to denial of service and privilege escalation vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to
  the graphic acceleration functions used in VMware Tools for OSX handle
  memory incorrectly." );
	script_tag( name: "impact", value: "Successful exploitation will allow local
  users to gain privileges or cause a denial of service." );
	script_tag( name: "affected", value: "VMware Tools 9.x and 10.x before 10.0.9
  on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to VMware Tool version 10.0.9 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2016-0014.html" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_vmware_tools_detect_macosx.sc" );
	script_mandatory_keys( "VMwareTools/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vmtoolVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( vmtoolVer, "^(9|10)" )){
	if(version_is_less( version: vmtoolVer, test_version: "10.0.9" )){
		report = report_fixed_ver( installed_version: vmtoolVer, fixed_version: "10.0.9" );
		security_message( data: report );
		exit( 0 );
	}
}

