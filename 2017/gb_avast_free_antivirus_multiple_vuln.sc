CPE = "cpe:/a:avast:antivirus";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811020" );
	script_version( "2021-09-16T13:01:47+0000" );
	script_cve_id( "CVE-2017-8308", "CVE-2017-8307" );
	script_bugtraq_id( 98084, 98086 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-16 13:01:47 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-05-05 12:59:15 +0530 (Fri, 05 May 2017)" );
	script_name( "Avast Free Antivirus Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with Avast Free
  Antivirus and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to design errors in
  the application. Using LPC interface API exposed by the AvastSVC.exe Windows
  service it is possible to delete arbitrary file, replace arbitrary file and
  launch predefined binaries." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to conduct a denial-of-service condition, execute arbitrary code and bypass
  certain security features on the affected system." );
	script_tag( name: "affected", value: "Avast Free Antivirus version prior to
  version 17.0." );
	script_tag( name: "solution", value: "Upgrade to Avast Free Antivirus version
  17.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.trustwave.com/Resources/Security-Advisories/Advisories/Multiple-Vulnerabilities-in-Avast-Antivirus/?fid=9201" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_avast_av_detect_win.sc" );
	script_mandatory_keys( "avast/antivirus_free/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "17.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "17.0", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

