CPE = "cpe:/o:d-link:dir-850l_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813008" );
	script_version( "2021-05-26T06:00:13+0200" );
	script_cve_id( "CVE-2017-3193" );
	script_bugtraq_id( 96747 );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-05-26 06:00:13 +0200 (Wed, 26 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:27:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-03-08 16:47:29 +0530 (Thu, 08 Mar 2018)" );
	script_name( "D-Link DIR-850L 'CVE-2017-3193' Stack-Based Buffer Overflow Vulnerability" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dlink_dir_detect.sc" );
	script_mandatory_keys( "d-link/dir/fw_version", "d-link/dir/hw_version" );
	script_xref( name: "URL", value: "https://www.kb.cert.org/vuls/id/305448" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/viewAlert.x?alertId=52967" );
	script_tag( name: "summary", value: "This host has D-Link DIR-850L device
  and is prone to a buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an insufficient
  validation of user-supplied input in the web administration interface of
  the affected system." );
	script_tag( name: "impact", value: "Successfully exploitation will allow remote
  attackers to conduct arbitrary code execution. Failed exploit attempts will
  likely cause a denial-of-service condition." );
	script_tag( name: "affected", value: "D-Link DIR-850L, firmware versions 1.14B07,
  2.07.B05, and possibly others." );
	script_tag( name: "solution", value: "Upgrade to beta firmware releases (versions
  1.14B07 h2ab BETA1 and 2.07B05 h1ke BETA1, depending on the device's hardware
  revision)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!fw_vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(!hw_vers = get_kb_item( "d-link/dir/hw_version" )){
	exit( 0 );
}
hw_vers = toupper( hw_vers );
fw_vers = toupper( fw_vers );
if(IsMatchRegexp( hw_vers, "^A" ) && version_is_less_equal( version: fw_vers, test_version: "1.14B07" )){
	VULN = TRUE;
	fix = "1.14B07 h2ab BETA1";
}
if(IsMatchRegexp( hw_vers, "^B" ) && version_is_less_equal( version: fw_vers, test_version: "2.07B05" )){
	VULN = TRUE;
	fix = "2.07B05 h1ke BETA1";
}
if(VULN){
	report = report_fixed_ver( installed_version: fw_vers, fixed_version: fix, extra: "Hardware revision: " + hw_vers );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

