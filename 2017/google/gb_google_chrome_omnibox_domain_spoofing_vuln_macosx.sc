CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811886" );
	script_version( "2021-09-17T09:09:50+0000" );
	script_cve_id( "CVE-2017-5090" );
	script_bugtraq_id( 101591 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-17 09:09:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-14 16:21:00 +0000 (Tue, 14 Nov 2017)" );
	script_tag( name: "creation_date", value: "2017-11-02 17:19:50 +0530 (Thu, 02 Nov 2017)" );
	script_name( "Google Chrome Omnibox Domain Spoofing Vulnerability - MAC OS X" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to a domain spoofing vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an insufficient
  policy enforcement in Omnibox in Google Chrome." );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote attackers to perform domain spoofing
  via a crafted domain name, this may aid in launching further attacks." );
	script_tag( name: "affected", value: "Google Chrome version prior to
  59.0.3071.115 on MAC OS X." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  59.0.3071.115 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://bugs.chromium.org/p/chromium/issues/detail?id=725660" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_macosx.sc" );
	script_mandatory_keys( "GoogleChrome/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
chr_ver = "";
if(!chr_ver = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: chr_ver, test_version: "59.0.3071.115" )){
	report = report_fixed_ver( installed_version: chr_ver, fixed_version: "59.0.3071.115" );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

