CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811100" );
	script_version( "2021-09-09T11:01:33+0000" );
	script_cve_id( "CVE-2017-5031" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-09 11:01:33 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-12 01:29:00 +0000 (Tue, 12 Jun 2018)" );
	script_tag( name: "creation_date", value: "2017-05-08 10:44:05 +0530 (Mon, 08 May 2017)" );
	script_name( "Mozilla Firefox Security Updates(mfsa_2017-14_2017-14)-Windows" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox
  and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to a use-after-free can
  occur during Buffer11 API calls within the ANGLE graphics library, used for WebGL
  content. This can lead to a potentially exploitable crash." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause denial of service." );
	script_tag( name: "affected", value: "Mozilla Firefox version before 53.0.2 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 53.0.2
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2017-14" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!ffVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: ffVer, test_version: "53.0.2" )){
	report = report_fixed_ver( installed_version: ffVer, fixed_version: "53.0.2" );
	security_message( data: report );
	exit( 0 );
}

