CPE = "cpe:/a:dokuwiki:dokuwiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902734" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-09-30 15:58:03 +0200 (Fri, 30 Sep 2011)" );
	script_cve_id( "CVE-2011-3727" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "DokuWiki '.php' Files Information Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dokuwiki_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "dokuwiki/installed" );
	script_xref( name: "URL", value: "http://www.security-database.com/detail.php?alert=CVE-2011-3727" );
	script_xref( name: "URL", value: "https://www.infosecisland.com/alertsview/16752-CVE-2011-3727-dokuwiki.html" );
	script_xref( name: "URL", value: "http://code.google.com/p/inspathx/source/browse/trunk/paths_vuln/dokuwiki-2009-12-25c" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to gain sensitive
  information." );
	script_tag( name: "affected", value: "DokuWiki version 2009-12-25c." );
	script_tag( name: "insight", value: "The flaw is due to error in certain '.php' files. A direct
  request to these files reveals the installation path in an error message." );
	script_tag( name: "solution", value: "Upgrade to DokuWiki version dokuwiki-20121013 or later." );
	script_tag( name: "summary", value: "The host is running DokuWiki and is prone to information
  disclosure vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "http://www.splitbrain.org/projects/dokuwiki" );
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
url = dir + "/lib/tpl/index.php";
if(http_vuln_check( port: port, url: url, pattern: "<b>Warning</b>:  define\\(\\)" + " expects at least 2 parameters.*lib/tpl/index.php" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

