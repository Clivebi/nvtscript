CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808579" );
	script_version( "2021-09-08T12:28:17+0000" );
	script_cve_id( "CVE-2016-4172", "CVE-2016-4173", "CVE-2016-4174", "CVE-2016-4175", "CVE-2016-4176", "CVE-2016-4177", "CVE-2016-4178", "CVE-2016-4179", "CVE-2016-4180", "CVE-2016-4181", "CVE-2016-4182", "CVE-2016-4183", "CVE-2016-4184", "CVE-2016-4185", "CVE-2016-4186", "CVE-2016-4187", "CVE-2016-4188", "CVE-2016-4189", "CVE-2016-4190", "CVE-2016-4217", "CVE-2016-4218", "CVE-2016-4219", "CVE-2016-4220", "CVE-2016-4221", "CVE-2016-4222", "CVE-2016-4223", "CVE-2016-4224", "CVE-2016-4225", "CVE-2016-4226", "CVE-2016-4227", "CVE-2016-4228", "CVE-2016-4229", "CVE-2016-4230", "CVE-2016-4231", "CVE-2016-4232", "CVE-2016-4233", "CVE-2016-4234", "CVE-2016-4235", "CVE-2016-4236", "CVE-2016-4237", "CVE-2016-4238", "CVE-2016-4239", "CVE-2016-4240", "CVE-2016-4241", "CVE-2016-4242", "CVE-2016-4243", "CVE-2016-4244", "CVE-2016-4245", "CVE-2016-4246", "CVE-2016-4247", "CVE-2016-4248", "CVE-2016-4249", "CVE-2016-7020" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-08 12:28:17 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-07-13 08:56:08 +0530 (Wed, 13 Jul 2016)" );
	script_name( "Adobe Flash Player Security Update (apsb16-25) - Linux" );
	script_tag( name: "summary", value: "Adobe Flash Player is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A race condition vulnerability.

  - A type confusion vulnerabilities.

  - An use-after-free vulnerabilities.

  - A heap buffer overflow vulnerability.

  - A memory corruption vulnerabilities.

  - A stack corruption vulnerabilities.

  - A security bypass vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote attackers lead to information disclosure,
  and code execution." );
	script_tag( name: "affected", value: "Adobe Flash Player version before
  11.2.202.632." );
	script_tag( name: "solution", value: "Update to version 11.2.202.632 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb16-25.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_lin.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Linux/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "11.2.202.632" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "11.2.202.632", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

