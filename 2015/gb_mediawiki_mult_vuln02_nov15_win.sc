CPE = "cpe:/a:mediawiki:mediawiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806632" );
	script_version( "2020-11-05T11:58:57+0000" );
	script_cve_id( "CVE-2013-6451", "CVE-2013-6452", "CVE-2013-6453", "CVE-2013-6454", "CVE-2013-6472" );
	script_bugtraq_id( 65003 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-11-05 11:58:57 +0000 (Thu, 05 Nov 2020)" );
	script_tag( name: "creation_date", value: "2015-11-26 16:21:27 +0530 (Thu, 26 Nov 2015)" );
	script_name( "MediaWiki Multiple Vulnerabilities -02 Nov15 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with MediaWiki
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error which displays some information about deleted pages in the log
  API, enhanced RecentChanges, and user watchlists.

  - An error in CSS whose sanitization did not filter -o-link attributes.

  - An error leading SVG sanitization to bypass when the XML was considered
  invalid.

  - An error in SVG files upload that could lead to include external stylesheets
  in upload." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct XSS attacks, gain access to sensitive information and
  have other some unspecified impact." );
	script_tag( name: "affected", value: "MediaWiki before 1.19.10, 1.2x before 1.21.4,
  and 1.22.x before 1.22.1 on Windows." );
	script_tag( name: "solution", value: "Upgrade to version 1.19.10 or 1.21.4 or
  1.22.1 or later." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://lists.wikimedia.org/pipermail/mediawiki-announce/2014-January/000138.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_mediawiki_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mediawiki/installed", "Host/runs_windows" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if( version_is_less( version: vers, test_version: "1.19.10" ) ){
	fix = "1.19.10";
	VULN = TRUE;
}
else {
	if( version_in_range( version: vers, test_version: "1.20", test_version2: "1.21.3" ) ){
		fix = "1.21.4";
		VULN = TRUE;
	}
	else {
		if(version_is_equal( version: vers, test_version: "1.22.0" )){
			fix = "1.22.1";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

