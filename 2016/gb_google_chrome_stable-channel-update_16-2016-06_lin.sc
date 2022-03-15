CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808233" );
	script_version( "2021-09-20T13:02:01+0000" );
	script_cve_id( "CVE-2016-1704" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-20 13:02:01 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "creation_date", value: "2016-06-21 13:31:03 +0530 (Tue, 21 Jun 2016)" );
	script_name( "Google Chrome Security Updates(stable-channel-update_16-2016-06)-Linux" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaws exist due to there is a hidden
  prototype, and 'documentWrapper->GetPrototype()' actually returns itself, or
  fallbacked attributes are data-type properties." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause some unspecified impact." );
	script_tag( name: "affected", value: "Google Chrome version
  prior to 51.0.2704.103 on Linux" );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  51.0.2704.103 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2016/06/stable-channel-update_16.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "Google-Chrome/Linux/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!chr_ver = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: chr_ver, test_version: "51.0.2704.103" )){
	report = report_fixed_ver( installed_version: chr_ver, fixed_version: "51.0.2704.103" );
	security_message( data: report );
	exit( 0 );
}
