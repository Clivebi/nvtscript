CPE = "cpe:/a:adobe:adobe_air";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805587" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2015-3108", "CVE-2015-3107", "CVE-2015-3106", "CVE-2015-3105", "CVE-2015-3104", "CVE-2015-3103", "CVE-2015-3102", "CVE-2015-3101", "CVE-2015-3100", "CVE-2015-3099", "CVE-2015-3098", "CVE-2015-3096" );
	script_bugtraq_id( 75084, 75087, 75086, 75081, 75080, 75089, 75085, 75088 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-06-15 12:26:21 +0530 (Mon, 15 Jun 2015)" );
	script_name( "Adobe Air Multiple Vulnerabilities - 01 June15 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Air and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error which does not properly restrict discovery of memory addresseses.

  - Multiple use-after-free errors.

  - A memory corruption error.

  - An integer overflow error.

  - Multiple unspecified errors bypassing same origin policy.

  - An error due to permission issue in the flash broker for internet explorer.

  - A stack overflow error.

  - An unspecified error." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to disclose potentially sensitive information, execute arbitrary code,
  cause a denial of service, bypass the same origin policy and bypass certain
  protection mechanism." );
	script_tag( name: "affected", value: "Adobe Air versions before 18.0.0.144 on
  Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Air version 18.0.0.144
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb15-11.html" );
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
if(version_is_less( version: vers, test_version: "18.0.0.144" )){
	report = "Installed version: " + vers + "\n" + "Fixed version:     " + "18.0.0.144" + "\n";
	security_message( data: report );
	exit( 0 );
}

