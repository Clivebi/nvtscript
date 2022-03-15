CPE = "cpe:/a:mediawiki:mediawiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100733" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-08-02 14:28:14 +0200 (Mon, 02 Aug 2010)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2010-2787" );
	script_bugtraq_id( 42019 );
	script_name( "MediaWiki 'api.php' Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_mediawiki_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "mediawiki/installed" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/42019" );
	script_xref( name: "URL", value: "http://lists.wikimedia.org/pipermail/mediawiki-announce/2010-July/000092.html" );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to gain access to sensitive
  information, that may aid in further attacks." );
	script_tag( name: "affected", value: "MediaWiki 1.8 through 1.15.4 are vulnerable." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "MediaWiki is prone to an information-disclosure vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "1.8", test_version2: "1.15.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.15.5" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

