CPE = "cpe:/a:icewarp:mail_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800097" );
	script_version( "2020-11-05T10:18:37+0000" );
	script_tag( name: "last_modification", value: "2020-11-05 10:18:37 +0000 (Thu, 05 Nov 2020)" );
	script_tag( name: "creation_date", value: "2009-01-09 13:48:55 +0100 (Fri, 09 Jan 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2008-5734" );
	script_name( "Merak Mail Server Web Mail < 9.4.0 IMG HTML Tag Script Insertion Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/32770" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/47533" );
	script_xref( name: "URL", value: "http://blog.vijatov.com/index.php?itemid=11" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_icewarp_consolidation.sc" );
	script_mandatory_keys( "icewarp/mailserver/http/detected" );
	script_tag( name: "impact", value: "Successful exploitation could result in insertion of arbitrary HTML and
  script code via a specially crafted email in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "Merak Mail Server 9.3.2 and prior." );
	script_tag( name: "solution", value: "Upgrade to Merak Mail Server 9.4.0." );
	script_tag( name: "summary", value: "The host is running Merak Mail Server and is prone to script injection
  vulnerability. Input passed via <IMG> HTML tags in emails are not properly sanitised before being displayed in
  the users system." );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(version_is_less( version: vers, test_version: "9.4.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "9.4.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

