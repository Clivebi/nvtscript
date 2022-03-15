if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802427" );
	script_version( "2021-03-11T10:58:32+0000" );
	script_bugtraq_id( 52834 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-03-11 10:58:32 +0000 (Thu, 11 Mar 2021)" );
	script_tag( name: "creation_date", value: "2012-04-04 11:17:27 +0530 (Wed, 04 Apr 2012)" );
	script_name( "ArticleSetup Multiple Cross-Site Scripting and SQL Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://secpod.org/blog/?p=497" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18682/" );
	script_xref( name: "URL", value: "http://secpod.org/advisories/SecPod_ArticleSetup_Multiple_Vuln.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute
  arbitrary web script or HTML in a user's browser session in the context of
  an affected site and manipulate SQL queries by injecting arbitrary SQL code." );
	script_tag( name: "affected", value: "ArticleSetup version 1.11 and prior." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Input passed to 'userid' and 'password' parameter in '/upload/login.php'
  and '/upload/admin/login.php' page is not properly verified before being used.

  - Input passed to the 'cat' parameter in 'upload/feed.php', 's' parameter in
  'upload/search.php', 'id' parameter in '/upload/admin/pageedit.php',
  'upload/admin/authoredit.php' and '/admin/categoryedit.php' pages are  not
  properly verified before being used.

  - Input passed to the 'title' parameter in 'upload//author/submit.php',
  '/upload/admin/articlenew.php', '/upload/admin/categories.php' and
  '/upload/admin/pages.php' pages are not properly verified before being used." );
	script_tag( name: "solution", value: "No known solution was made available for at least one
  year since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "ArticleSetup is prone to multiple cross-site scripting
  and SQL injection vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/ArticleSetup", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	if(http_vuln_check( port: port, url: dir + "/upload/index.php", pattern: ">Art" + "icle Script</", extra_check: make_list( ">Most Viewed",
		 "All Categories<",
		 ">Submit Articles<" ), usecache: TRUE )){
		exploits = make_list( "/upload/search.php?s='",
			 "/upload/search.php?s=<script>alert(document.cookie)</script>" );
		for exploit in exploits {
			url = dir + exploit;
			if(http_vuln_check( port: port, url: url, pattern: "You have an error in your SQL syntax|<script>alert\\(docum" + "ent\\.cookie\\)</script>", extra_check: make_list( ">Submit Articles<",
				 "All" + " Categories<" ), check_header: TRUE )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

