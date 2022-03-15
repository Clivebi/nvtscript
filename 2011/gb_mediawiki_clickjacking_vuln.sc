CPE = "cpe:/a:mediawiki:mediawiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801900" );
	script_version( "$Revision: 14012 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-06 10:13:44 +0100 (Wed, 06 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-04 14:32:35 +0100 (Fri, 04 Mar 2011)" );
	script_cve_id( "CVE-2011-0003" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_name( "MediaWiki Frames Processing Clickjacking Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_mediawiki_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "mediawiki/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42810" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/64476" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/0017" );
	script_xref( name: "URL", value: "http://lists.wikimedia.org/pipermail/mediawiki-announce/2011-January/000093.html" );
	script_tag( name: "impact", value: "Successful exploitation will let remote attackers to hijack the victim's
  click actions and possibly launch further attacks against the victim." );
	script_tag( name: "affected", value: "MediaWiki version prior to 1.16.1." );
	script_tag( name: "insight", value: "The flaw is caused by input validation errors when processing certain data
  via frames, which could allow clickjacking attacks." );
	script_tag( name: "solution", value: "Upgrade to MediaWiki 1.16.1 or later." );
	script_tag( name: "summary", value: "This host is running MediaWiki and clickjacking information disclosure
  vulnerability." );
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
if(version_is_less( version: vers, test_version: "1.16.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.16.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

