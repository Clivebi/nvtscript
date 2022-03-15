if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107312" );
	script_version( "2021-06-03T02:00:18+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 02:00:18 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-11 16:37:09 +0200 (Fri, 11 May 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-10115" );
	script_name( "7zip RAR Denial of Service Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_7zip_detect_portable_win.sc" );
	script_mandatory_keys( "7zip/Win/Ver" );
	script_tag( name: "summary", value: "7zip is prone to a RAR Denial of Service Vulnerability." );
	script_tag( name: "vuldetect", value: "The script checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Incorrect initialization logic of RAR decoder objects in 7-Zip 18.03 and before
  can lead to usage of uninitialized memory, allowing remote attackers to cause a denial of service (segmentation fault)
  or execute arbitrary code via a crafted RAR archive." );
	script_tag( name: "affected", value: "7zip through version 18.03." );
	script_tag( name: "solution", value: "Upgrade to 7zip version 18.05 or later." );
	script_xref( name: "URL", value: "https://sourceforge.net/p/sevenzip/discussion/45797/thread/e730c709/?limit=25&page=1#b240" );
	exit( 0 );
}
CPE = "cpe:/a:7-zip:7-zip";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "18.05" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "18.05", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

