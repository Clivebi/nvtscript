CPE = "cpe:/a:adobe:tcs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814313" );
	script_version( "2021-05-31T06:00:15+0200" );
	script_cve_id( "CVE-2018-15976" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-05-31 06:00:15 +0200 (Mon, 31 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-17 16:21:00 +0000 (Mon, 17 Dec 2018)" );
	script_tag( name: "creation_date", value: "2018-10-12 10:15:17 +0530 (Fri, 12 Oct 2018)" );
	script_name( " Adobe TCS Privilege Escalation Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is running Adobe TCS and is prone
  to privilege escalation vulnerability" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to insecure .dll loading
  mechanism when opening files. A local attacker can place a file along with specially
  crafted .dll file on a remote SBM or WebDAV share, trick the victim into opening it
  and execute arbitrary code on the target system with privileges of the current victim." );
	script_tag( name: "impact", value: "Successful exploitation allows a local attacker
  to gain elevated privileges and compromise the vulnerable system." );
	script_tag( name: "affected", value: "Adobe TCS versions 7.1.57 and prior." );
	script_tag( name: "solution", value: "Update to Adobe TCS 2019 Release or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/techcommsuite/apsb18-38.html" );
	script_xref( name: "URL", value: "https://www.cybersecurity-help.cz/vdb/SB2018100909?affChecked=1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Privilege escalation" );
	script_dependencies( "gb_adobe_technical_comm_suite_detect_win.sc" );
	script_mandatory_keys( "AdobeTCS/Win/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
tcsVer = infos["version"];
tcsPath = infos["location"];
if(version_is_less( version: tcsVer, test_version: "7.1.57" )){
	report = report_fixed_ver( installed_version: tcsVer, fixed_version: "2019 Release", install_path: tcsPath );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

