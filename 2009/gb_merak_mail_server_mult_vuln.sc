CPE = "cpe:/a:icewarp:mail_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800388" );
	script_version( "2020-11-05T10:18:37+0000" );
	script_tag( name: "last_modification", value: "2020-11-05 10:18:37 +0000 (Thu, 05 Nov 2020)" );
	script_tag( name: "creation_date", value: "2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-1467", "CVE-2009-1468", "CVE-2009-1469" );
	script_bugtraq_id( 34823, 34820, 34827, 34825 );
	script_name( "IceWarp Merak Mail Server < 9.4.2 Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/1253" );
	script_xref( name: "URL", value: "http://www.redteam-pentesting.de/advisories/rt-sa-2009-001" );
	script_xref( name: "URL", value: "http://www.redteam-pentesting.de/advisories/rt-sa-2009-002" );
	script_xref( name: "URL", value: "http://www.redteam-pentesting.de/advisories/rt-sa-2009-003" );
	script_xref( name: "URL", value: "http://www.redteam-pentesting.de/advisories/rt-sa-2009-004" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_icewarp_consolidation.sc" );
	script_mandatory_keys( "icewarp/mailserver/http/detected" );
	script_tag( name: "impact", value: "Successful attacks will allow attackers to inject arbitrary web script or
  HTML script code via a specially crafted email in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "Merak Mail Server prior to 9.4.2." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to Merak Mail Server 9.4.2." );
	script_tag( name: "summary", value: "The host is running Merak Mail Server and is prone to multiple Cross-Site Scripting
  vulnerabilities." );
	script_tag( name: "insight", value: "- Error in cleanHTML function in server/inc/tools.php is related to the email
  view and incorrect processing of HTML filtering.

  - Error in getHTML function in server/inc/rss/item.php is related to title, link, or description element in an RSS feed.

  - Error exists in search form in server/webmail.php in the Groupware component via 'sql' and 'order_by' elements
  in an XML search query.

  - Error occur in Forgot Password implementation in server/webmail.php via CRLF sequences preceding a Reply-To
  header in the subject element of an XML document." );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "9.4.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "9.4.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

