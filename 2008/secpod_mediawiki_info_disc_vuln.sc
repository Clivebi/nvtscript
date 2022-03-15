CPE = "cpe:/a:mediawiki:mediawiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900422" );
	script_version( "2021-09-01T13:34:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 13:34:42 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2008-12-31 15:14:17 +0100 (Wed, 31 Dec 2008)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2008-5687", "CVE-2008-5688" );
	script_name( "MediaWiki Information Disclosure Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_mediawiki_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "mediawiki/installed" );
	script_xref( name: "URL", value: "http://www.mediawiki.org/wiki/Manual:$wgShowExceptionDetails" );
	script_xref( name: "URL", value: "http://lists.wikimedia.org/pipermail/mediawiki-announce/2008-December/000080.html" );
	script_tag( name: "impact", value: "Successful exploitation will lead to gain knowledge on sensitive directories
  on the remote web server via requests." );
	script_tag( name: "affected", value: "MediaWiki version 1.8.1 to 1.13.3

  MediaWiki version 1.11 to 1.13.3" );
	script_tag( name: "insight", value: "The flaws are due to:

  - wgShowExceptionDetails variable sometimes shows the installation path of
  MediaWiki which can lead to expose sensitive information about the remote system.

  - fails to protect against the download of backups of deleted images in
  images/deleted/." );
	script_tag( name: "solution", value: "Upgrade to MediaWiki Version 1.15.4 or later." );
	script_tag( name: "summary", value: "This host is running MediaWiki and is prone to Information
  Disclosure Vulnerabilities." );
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
if(version_in_range( version: vers, test_version: "1.8.1", test_version2: "1.13.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.15.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

