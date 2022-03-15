if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113349" );
	script_version( "2021-09-02T13:01:30+0000" );
	script_tag( name: "last_modification", value: "2021-09-02 13:01:30 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-03-06 12:37:03 +0200 (Wed, 06 Mar 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:39:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-20253" );
	script_name( "WinRAR <= 5.60 Out-of-Bounds Write Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_winrar_detect.sc" );
	script_mandatory_keys( "WinRAR/Ver" );
	script_tag( name: "summary", value: "WinRAR is prone to an Out-of-Bounds Write Vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability can be exploited by bringing a user to parse a specially
  crafted LHA or LZH archive." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to execute arbitrary code
  in the context of the current user." );
	script_tag( name: "affected", value: "WinRAR through version 5.60." );
	script_tag( name: "solution", value: "Update to version 5.61." );
	exit( 0 );
}
CPE = "cpe:/a:rarlab:winrar";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "5.61" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.61", install_path: path );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

