CPE = "cpe:/h:intel:active_management_technology";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813800" );
	script_version( "2021-06-22T02:00:27+0000" );
	script_cve_id( "CVE-2018-3628", "CVE-2018-3629", "CVE-2018-3632" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-07-24 13:43:57 +0530 (Tue, 24 Jul 2018)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Intel Active Management Technology Buffer Overflow And Memory Corruption Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with Intel Active
  Management Technology and is prone to multiple buffer overflow and memory
  corruption vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple unspecified
  buffer overflow and memory corruption errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute arbitrary code, cause a denial of service via the same subnet and also
  gain elevated privileges on the system." );
	script_tag( name: "affected", value: "Intel Active Management Technology versions
  3.x/4.x/5.x/6.x/7.x/8.x/9.x/10.x/11.x." );
	script_tag( name: "solution", value: "Upgrade to an appropriate Intel CSME firmware
  version. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00112.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_intel_amt_webui_detect.sc" );
	script_mandatory_keys( "intel_amt/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!imePort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: imePort, exit_no_version: TRUE )){
	exit( 0 );
}
imeVer = infos["version"];
imepath = infos["location"];
if(IsMatchRegexp( imeVer, "^((3|4|5|6|7|8|9|10|11)\\.)" )){
	report = report_fixed_ver( installed_version: imeVer, fixed_version: "See references", install_path: imepath );
	security_message( port: imePort, data: report );
	exit( 0 );
}
exit( 0 );

