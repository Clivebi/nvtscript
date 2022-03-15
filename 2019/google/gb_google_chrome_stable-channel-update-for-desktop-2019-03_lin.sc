CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814690" );
	script_version( "2021-09-08T09:01:34+0000" );
	script_cve_id( "CVE-2019-5786" );
	script_bugtraq_id( 107213 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-08 09:01:34 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-01 18:26:00 +0000 (Mon, 01 Jul 2019)" );
	script_tag( name: "creation_date", value: "2019-03-05 14:59:59 +0530 (Tue, 05 Mar 2019)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-for-desktop-2019-03)-Linux" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to arbitrary code execution vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an use after free error
  in FileReader." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code in the context of the browser, Failed attempts will
  likely cause a denial-of-service condition." );
	script_tag( name: "affected", value: "Google Chrome version prior to 72.0.3626.121
  on Linux" );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  72.0.3626.121 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2019/03/stable-channel-update-for-desktop.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "Google-Chrome/Linux/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "72.0.3626.121" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "72.0.3626.121", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

