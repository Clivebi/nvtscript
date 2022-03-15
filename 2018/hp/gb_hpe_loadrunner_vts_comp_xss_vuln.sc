CPE = "cpe:/a:hp:loadrunner";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812938" );
	script_version( "2021-06-15T02:00:29+0000" );
	script_cve_id( "CVE-2017-8953" );
	script_bugtraq_id( 100338 );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-06-15 02:00:29 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-07 20:31:00 +0000 (Wed, 07 Mar 2018)" );
	script_tag( name: "creation_date", value: "2018-02-19 15:32:13 +0530 (Mon, 19 Feb 2018)" );
	script_name( "HPE LoadRunner Virtual Table Server (VTS) Component Cross-Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with HPE LoadRunner
  and is prone to a cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to potential errors in
  the Virtual Table Server (VTS) component of application." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to execute arbitrary script code in the browser of an unsuspecting
  user in the context of the affected site." );
	script_tag( name: "affected", value: "HPE LoadRunner version 12.53 and earlier." );
	script_tag( name: "solution", value: "Upgrade to HPE LoadRunner to version 12.55
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbgn03764en_us" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "gb_hpe_loadrunner_detect.sc" );
	script_mandatory_keys( "HPE/LoadRunner/Win/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "12.55.646.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "12.55", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

