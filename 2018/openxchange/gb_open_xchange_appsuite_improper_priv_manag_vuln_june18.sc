CPE = "cpe:/a:open-xchange:open-xchange_appsuite";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813445" );
	script_version( "2021-06-25T02:56:08+0000" );
	script_cve_id( "CVE-2017-17062" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-06-25 02:56:08 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-06-19 12:05:29 +0530 (Tue, 19 Jun 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Open-Xchange (OX) AppSuite Improper Privilege Management Vulnerability-June18" );
	script_tag( name: "summary", value: "The host is installed with Open-Xchange (OX)
  AppSuite and is prone to improper privilege management vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in
  the backend component in Open-Xchange OX App Suite where certain 'user
  attributes' can be saved by using arbitrary users identifiers within the same
  context." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to void non-repudiation, as there seems no way to access other users attributes." );
	script_tag( name: "affected", value: "Open-Xchange OX App Suite before 7.6.3-rev35,
  7.8.x before 7.8.2-rev38, 7.8.3 before 7.8.3-rev41, and 7.8.4 before 7.8.4-rev19" );
	script_tag( name: "solution", value: "Upgrade to Open-Xchange (OX) AppSuite
  version 7.6.3-rev35 or 7.8.2-rev38 or 7.8.3-rev41 or 7.8.4-rev19 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/44881" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2018/Jun/23" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/148118" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ox_app_suite_detect.sc" );
	script_mandatory_keys( "open_xchange_appsuite/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!oxPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: oxPort, exit_no_version: TRUE )){
	exit( 0 );
}
oxVer = infos["version"];
path = infos["location"];
oxRev = get_kb_item( "open_xchange_appsuite/" + oxPort + "/revision" );
if(!oxRev){
	exit( 0 );
}
oxVer = oxVer + "." + oxRev;
if( version_is_less( version: oxVer, test_version: "7.6.3.35" ) ){
	fix = "7.6.3-rev35";
}
else {
	if( version_in_range( version: oxVer, test_version: "7.8.2", test_version2: "7.8.2.37" ) ){
		fix = "7.8.2-rev38";
	}
	else {
		if( version_in_range( version: oxVer, test_version: "7.8.3", test_version2: "7.8.3.40" ) ){
			fix = "7.8.3-rev41";
		}
		else {
			if(version_in_range( version: oxVer, test_version: "7.8.4", test_version2: "7.8.4.18" )){
				fix = "7.8.4-rev19";
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: oxVer, fixed_version: fix, install_path: path );
	security_message( data: report, port: oxPort );
	exit( 0 );
}
exit( 0 );

