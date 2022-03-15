CPE = "cpe:/a:adobe:bridge_cc";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815242" );
	script_version( "2021-08-30T13:01:21+0000" );
	script_cve_id( "CVE-2019-7963" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-30 13:01:21 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-22 11:53:00 +0000 (Mon, 22 Jul 2019)" );
	script_tag( name: "creation_date", value: "2019-07-11 11:03:17 +0530 (Thu, 11 Jul 2019)" );
	script_name( "Adobe Bridge CC Security Updates (apsb19-37)-Windows" );
	script_tag( name: "summary", value: "The host is installed with Adobe Bridge CC
  and is prone to an information disclosure vulnerability" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an out-of-bounds
  read error." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to obtain sensitive information that may aid in further attacks." );
	script_tag( name: "affected", value: "Adobe Bridge CC version 9.0.2 and before on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Bridge CC 9.1 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/bridge/apsb19-37.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_bridge_cc_detect.sc" );
	script_mandatory_keys( "Adobe/Bridge/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "9.1.0.338" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: " 9.1 (9.1.0.338)", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

