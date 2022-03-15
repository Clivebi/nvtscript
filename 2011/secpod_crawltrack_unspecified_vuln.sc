if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901179" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-02-05 04:12:38 +0100 (Sat, 05 Feb 2011)" );
	script_cve_id( "CVE-2010-4537" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "CrawlTrack Unspecified Vulnerability" );
	script_xref( name: "URL", value: "http://www.crawltrack.net/changelog.php" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/3342" );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2011/01/03/7" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_crawltrack_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "crawltrack/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary PHP
  code with the privileges of the web server." );
	script_tag( name: "affected", value: "CrawlTrack versions before 3.2.7." );
	script_tag( name: "insight", value: "The flaw is caused by input validation errors in the stats pages when
  processing user-supplied data and parameters, which could allow remote
  attackers to execute arbitrary PHP code with the privileges of the web server." );
	script_tag( name: "solution", value: "Upgrade to CrawlTrack version 3.2.7 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The host is running CrawlTrack and is prone to unspecified
  vulnerability." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(ver = get_version_from_kb( port: port, app: "CrawlTrack" )){
	if(version_is_less( version: ver, test_version: "3.2.7" )){
		report = report_fixed_ver( installed_version: ver, fixed_version: "3.2.7" );
		security_message( port: port, data: report );
	}
}

