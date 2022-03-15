CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805504" );
	script_version( "2020-11-19T14:17:11+0000" );
	script_cve_id( "CVE-2015-1213", "CVE-2015-1214", "CVE-2015-1215", "CVE-2015-1216", "CVE-2015-1217", "CVE-2015-1218", "CVE-2015-1219", "CVE-2015-1220", "CVE-2015-1221", "CVE-2015-1222", "CVE-2015-1223", "CVE-2015-1224", "CVE-2015-1225", "CVE-2015-1226", "CVE-2015-1227", "CVE-2015-1228", "CVE-2015-1229", "CVE-2015-1230", "CVE-2015-1231", "CVE-2015-1232", "CVE-2015-1238", "CVE-2015-1239", "CVE-2015-1245", "CVE-2014-9689", "CVE-2011-5319" );
	script_bugtraq_id( 72901, 72916 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-11-19 14:17:11 +0000 (Thu, 19 Nov 2020)" );
	script_tag( name: "creation_date", value: "2015-03-13 14:48:07 +0530 (Fri, 13 Mar 2015)" );
	script_name( "Google Chrome Multiple Vulnerabilities-01 Mar15 (Mac OS X)" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist. Please see the
  references for more details." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to dereference already freed memory, potentially execute arbitrary code,
  potentially disclose memory contents, gain unauthorized access to information,
  cause a denial of service, conduct cookie-injection attacks and other unspecified
  impacts." );
	script_tag( name: "affected", value: "Google Chrome version prior to
  41.0.2272.76 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  41.0.2272.76 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://code.google.com/p/chromium/issues/detail?id=444957" );
	script_xref( name: "URL", value: "https://code.google.com/p/chromium/issues/detail?id=463349" );
	script_xref( name: "URL", value: "https://googlechromereleases.blogspot.com/2015/03/stable-channel-update.html" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_macosx.sc" );
	script_mandatory_keys( "GoogleChrome/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!chromeVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "41.0.2272.76" )){
	report = "Installed version: " + chromeVer + "\n" + "Fixed version:     41.0.2272.76" + "\n";
	security_message( data: report );
	exit( 0 );
}
