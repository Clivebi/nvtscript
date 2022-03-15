if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112688" );
	script_version( "2020-03-18T09:01:42+0000" );
	script_tag( name: "last_modification", value: "2020-03-18 09:01:42 +0000 (Wed, 18 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-01-14 12:34:05 +0000 (Tue, 14 Jan 2020)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-5278" );
	script_name( "Huawei GaussDB 100 OLTP: Cross-Border Access Vulnerability (huawei-sa-20191204-01-gauss100)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_gaussdb_consolidation.sc" );
	script_mandatory_keys( "huawei/gaussdb/detected" );
	script_tag( name: "summary", value: "There is an out-of-bounds read vulnerability in the
  Advanced Packages feature of the Huawei GaussDB 100 OLTP database." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Attackers who gain the specific permission can use this vulnerability by sending elaborate SQL statements to the database." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability may cause the database to crash." );
	script_tag( name: "affected", value: "Huawei GaussDB 100 OLTP versions:

  - V300R001C00SPC100

  - V300R001C00SPC200" );
	script_tag( name: "solution", value: "Update Huawei GaussDB 100 OLTP to version V300R001C00SPC201 to fix the issue." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20191204-01-gauss100-en" );
	exit( 0 );
}
CPE = "cpe:/a:huawei:gaussdb_100_oltp";
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(IsMatchRegexp( version, "v300r001c00spc[12]00" )){
	report = report_fixed_ver( installed_version: toupper( version ), fixed_version: "V300R001C00SPC201", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

