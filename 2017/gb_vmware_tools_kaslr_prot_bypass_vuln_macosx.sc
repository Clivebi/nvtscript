CPE = "cpe:/a:vmware:tools";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810267" );
	script_version( "2021-09-16T10:32:36+0000" );
	script_cve_id( "CVE-2016-5328" );
	script_bugtraq_id( 93886 );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-16 10:32:36 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-29 01:34:00 +0000 (Sat, 29 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-01-10 12:53:05 +0530 (Tue, 10 Jan 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "VMware Tools kASLR Protection Bypass Vulnerability (Mac OS X)" );
	script_tag( name: "summary", value: "The host is installed with VMware Tools
  and is prone to a security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified security
  bypass error when System Integrity Protection (SIP) is enabled." );
	script_tag( name: "impact", value: "Successful exploitation will allow local
  privileged users to obtain kernel memory addresses to bypass the kASLR
  protection mechanism." );
	script_tag( name: "affected", value: "VMware Tools 9.x and 10.x before 10.1.0
  on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to VMware Tool version 10.1.0 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2016-0017.html" );
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
	if(version_is_less( version: vmtoolVer, test_version: "10.1.0" )){
		report = report_fixed_ver( installed_version: vmtoolVer, fixed_version: "10.1.0" );
		security_message( data: report );
		exit( 0 );
	}
}

