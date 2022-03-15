CPE = "cpe:/a:openmairie:openannuaire";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800780" );
	script_version( "2021-08-04T02:26:48+0000" );
	script_tag( name: "last_modification", value: "2021-08-04 02:26:48 +0000 (Wed, 04 Aug 2021)" );
	script_tag( name: "creation_date", value: "2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-1921", "CVE-2010-1920" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "OpenMairie openAnnuaire Multiple Remote File Include Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_openmairie_prdts_http_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "openmairie/open_annuaire/http/detected" );
	script_tag( name: "insight", value: "Input passed to the parameter 'path_om' in various files and
  to the parameter 'dsn[phptype]' in 'scr/soustab.php' are not properly verified
  before being used to include files." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "summary", value: "OpenMairie openAnnuaire is prone to multiple remote file
  inclusion vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to obtain
  sensitive information or compromise a vulnerable system." );
	script_tag( name: "affected", value: "OpenMairie openAnnuaire version 2.00." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/39673" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/12486" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/1059" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/scr/soustab.php?dsn[phptype]=../../../../../../../../vt-rfi.txt";
req = http_get( port: port, item: url );
res = http_send_recv( port: port, data: req );
if(ContainsString( res, "/vt-rfi.txt/" ) && ContainsString( res, "failed to open stream" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

