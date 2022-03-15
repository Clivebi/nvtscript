CPE = "cpe:/a:vmware:fusion";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809793" );
	script_version( "2021-09-08T14:01:33+0000" );
	script_cve_id( "CVE-2016-5329" );
	script_bugtraq_id( 93888 );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-08 14:01:33 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-29 01:34:00 +0000 (Sat, 29 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-02-03 13:26:10 +0530 (Fri, 03 Feb 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "VMware Fusion 'kASLR' Information Disclosure Vulnerability (Mac OS X)" );
	script_tag( name: "summary", value: "The host is installed with VMware Fusion
  and is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified security
  bypass error when System Integrity Protection (SIP) is enabled." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  privileged local user on a system where System Integrity Protection (SIP)
  is enabled, to obtain kernel memory addresses to bypass the kASLR protection
  mechanism." );
	script_tag( name: "affected", value: "VMware Fusion 8.x before 8.5 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to VMware Fusion version 8.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2016-0017.html" );
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
	if(version_is_less( version: vmwareVer, test_version: "8.5" )){
		report = report_fixed_ver( installed_version: vmwareVer, fixed_version: "8.5" );
		security_message( data: report );
		exit( 0 );
	}
}

