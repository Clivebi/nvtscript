CPE = "cpe:/a:barracuda:web_filter";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105287" );
	script_bugtraq_id( 74384 );
	script_cve_id( "CVE-2015-0961", "CVE-2015-0962" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_name( "Barracuda Web Filter SSL Certificate Multiple Security Bypass Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/74384" );
	script_tag( name: "impact", value: "Successfully exploiting these issues allow attackers to perform man-in-the-
middle attacks or impersonate trusted servers, which will aid in further attacks." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Barracuda Web Filter when SSL Inspection is enabled, uses the same root Certification Authority certificate
across different customers' installations, which makes it easier for remote attackers to conduct man-in-the-middle attacks against SSL sessions
by leveraging the certificate's trust relationship" );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "summary", value: "Barracuda Web Filter is prone to multiple security-bypass vulnerabilities." );
	script_tag( name: "affected", value: "Barracuda Web Filter 7.x and 8.x before 8.1.0.005" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2015-06-03 16:03:11 +0200 (Wed, 03 Jun 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_barracuda_web_filter_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "barracuda_web_filter/installed" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(IsMatchRegexp( vers, "^7\\." ) || IsMatchRegexp( vers, "^8\\." )){
	if(version_is_less( version: vers, test_version: "8.1.0.005" )){
		report = "Installed version: " + vers + "\n" + "Fixed version:     8.1.0.005\n";
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

