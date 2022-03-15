CPE = "cpe:/a:oracle:vm_virtualbox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809078" );
	script_version( "2021-09-20T13:02:01+0000" );
	script_cve_id( "CVE-2016-5605" );
	script_bugtraq_id( 93685 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-20 13:02:01 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-29 01:34:00 +0000 (Sat, 29 Jul 2017)" );
	script_tag( name: "creation_date", value: "2016-10-21 14:40:28 +0530 (Fri, 21 Oct 2016)" );
	script_name( "Oracle Virtualbox VRDE Privilege Escalation Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Oracle VM
  VirtualBox and is prone to a privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified error in
  VirtualBox Remote Desktop Extension (VRDE) sub component." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to access and modify data." );
	script_tag( name: "affected", value: "VirtualBox versions prior to 5.1.4 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Oracle VirtualBox version
  5.1.4 or later on Windows." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "secpod_sun_virtualbox_detect_win.sc" );
	script_mandatory_keys( "Oracle/VirtualBox/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!virtualVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( virtualVer, "^5\\.1\\." )){
	if(version_is_less( version: virtualVer, test_version: "5.1.4" )){
		report = report_fixed_ver( installed_version: virtualVer, fixed_version: "5.1.4" );
		security_message( data: report );
		exit( 0 );
	}
}

