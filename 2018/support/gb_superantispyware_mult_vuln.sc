if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113099" );
	script_version( "2021-06-29T11:00:37+0000" );
	script_tag( name: "last_modification", value: "2021-06-29 11:00:37 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-01 13:06:12 +0100 (Thu, 01 Feb 2018)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-02-13 16:12:00 +0000 (Tue, 13 Feb 2018)" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_cve_id( "CVE-2018-6471", "CVE-2018-6472", "CVE-2018-6473", "CVE-2018-6474", "CVE-2018-6475", "CVE-2018-6476" );
	script_name( "SuperAntiSpyware 6.0.1254 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_superantispyware_detect.sc" );
	script_mandatory_keys( "superantispyware/detected" );
	script_tag( name: "summary", value: "SuperAntiSpyware 6.0.1254 is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "The script checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An attacker can write to the driver file. The input is not validated, leading
to possible BSOD or Privilege Escalation." );
	script_tag( name: "affected", value: "SuperAntiSpyware 6.0.1254" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://github.com/ZhiyuanWang-Chengdu-Qihoo360/SUPERAntiSpyware_POC" );
	exit( 0 );
}
CPE = "cpe:/a:superantispyware:superantispyware";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "6.0.1254" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "NoneAvailable" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 0 );

