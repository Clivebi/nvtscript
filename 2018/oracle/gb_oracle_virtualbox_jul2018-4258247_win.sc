CPE = "cpe:/a:oracle:vm_virtualbox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813580" );
	script_version( "2021-06-30T02:00:35+0000" );
	script_cve_id( "CVE-2018-3085", "CVE-2018-3087", "CVE-2018-3086", "CVE-2018-3090", "CVE-2018-3091", "CVE-2018-3089", "CVE-2018-3088", "CVE-2018-3055", "CVE-2018-3005" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-30 02:00:35 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-07-18 10:55:19 +0530 (Wed, 18 Jul 2018)" );
	script_name( "Oracle VirtualBox Security Updates (jul2018-4258247) (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Oracle VM
  VirtualBox and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to an improperly
  sanitized core component." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to escalate privileges, access and modify data and cause denial of service." );
	script_tag( name: "affected", value: "VirtualBox versions prior to 5.2.16 on
  Windows." );
	script_tag( name: "solution", value: "Upgrade to Oracle VirtualBox version 5.2.16
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html#AppendixOVIR" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(version_in_range( version: virtualVer, test_version: "5.2", test_version2: "5.2.15" )){
	report = report_fixed_ver( installed_version: virtualVer, fixed_version: "5.2.16" );
	security_message( data: report );
	exit( 0 );
}

