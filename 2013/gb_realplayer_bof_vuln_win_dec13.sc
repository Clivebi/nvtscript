CPE = "cpe:/a:realnetworks:realplayer";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804178" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-6877", "CVE-2013-7260" );
	script_bugtraq_id( 64398, 64695 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-12-26 11:34:28 +0530 (Thu, 26 Dec 2013)" );
	script_name( "RealNetworks RealPlayer Buffer Overflow Vulnerability Dec13 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with RealPlayer and is prone to buffer overflow
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to RealPlayer version 17.0.4.61 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "insight", value: "Flaw is due to:

  - An error in handling the 'version' and 'encoding' attributes in RMP files.

  - Improper validation of user input when handling the 'trackid' attribute in
  RMP files." );
	script_tag( name: "affected", value: "RealPlayer version before 17.0.4.61 on Windows." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote unauthenticated attacker to execute
arbitrary code with the privileges of the application." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/56219" );
	script_xref( name: "URL", value: "http://service.real.com/realplayer/security/12202013_player/en" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_realplayer_detect_win.sc" );
	script_mandatory_keys( "RealPlayer/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!rpVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: rpVer, test_version: "17.0.4.61" )){
	report = report_fixed_ver( installed_version: rpVer, fixed_version: "17.0.4.61" );
	security_message( port: 0, data: report );
	exit( 0 );
}

