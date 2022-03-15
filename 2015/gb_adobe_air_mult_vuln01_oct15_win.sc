CPE = "cpe:/a:adobe:adobe_air";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806096" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-5569", "CVE-2015-7625", "CVE-2015-7626", "CVE-2015-7627", "CVE-2015-7628", "CVE-2015-7629", "CVE-2015-7630", "CVE-2015-7631", "CVE-2015-7632", "CVE-2015-7633", "CVE-2015-7634", "CVE-2015-7635", "CVE-2015-7636", "CVE-2015-7637", "CVE-2015-7638", "CVE-2015-7639", "CVE-2015-7640", "CVE-2015-7641", "CVE-2015-7642", "CVE-2015-7643", "CVE-2015-7644" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-10-16 15:34:40 +0530 (Fri, 16 Oct 2015)" );
	script_name( "Adobe Air Multiple Vulnerabilities -01 Oct15 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Air
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Improper implementation of the Flash broker API.

  - Multiple memory corruption errors.

  - An use-after-free error.

  - An error in same origin policy.

  - A buffer overflow error." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to obtain sensitive information, execute arbitrary code or cause a denial of
  service and have other unspecified impacts." );
	script_tag( name: "affected", value: "Adobe Air versions before
  19.0.0.213 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Air version
  19.0.0.213 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb15-25.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_win.sc" );
	script_mandatory_keys( "Adobe/Air/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "19.0.0.213" )){
	report = "Installed version: " + vers + "\n" + "Fixed version:     " + "19.0.0.213" + "\n";
	security_message( data: report );
	exit( 0 );
}

