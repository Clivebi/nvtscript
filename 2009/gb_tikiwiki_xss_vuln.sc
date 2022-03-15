CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800266" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2009-04-16 16:39:16 +0200 (Thu, 16 Apr 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-1204" );
	script_bugtraq_id( 34105, 34106, 34107, 34108 );
	script_name( "Tiki Wiki CMS Groupware Multiple Cross Site Scripting Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_tikiwiki_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "TikiWiki/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to inject arbitrary HTML
  codes in the context of the affected web application." );
	script_tag( name: "affected", value: "Tiki Wiki CMS Groupware version 2.2, 2.3 and prior." );
	script_tag( name: "insight", value: "Multiple flaws are due to improper sanitization of user supplied input in
  the pages i.e. 'tiki-orphan_pages.php', 'tiki-listpages.php',
  'tiki-list_file_gallery.php' and 'tiki-galleries.php' which lets the attacker
  conduct XSS attacks inside the context of the web application." );
	script_tag( name: "solution", value: "Upgrade to Tiki Wiki CMS Groupware version 2.4 or later." );
	script_tag( name: "summary", value: "This host is running Tiki Wiki CMS Groupware and is prone to Multiple Cross Site Scripting
  vulnerabilities." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34273" );
	script_xref( name: "URL", value: "http://info.tikiwiki.org/tiki-read_article.php?articleId=51" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
urls = make_list( dir + "/tiki-listpages.php/<script>alert(\"XSS_Check\");</script>",
	 dir + "/tiki-galleries.php/<script>alert(\"XSS_Check\");</script>",
	 dir + "/tiki-orphan_pages.php/<script>alert(\"XSS_Check\");</script>",
	 dir + "/tiki-list_file_gallery.php/<script>alert(\"XSS_Check\");</script>" );
for url in urls {
	if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\(\"XSS_Check\"\\);</script>" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

