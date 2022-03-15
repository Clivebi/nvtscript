CPE = "cpe:/a:icewarp:mail_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902478" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-09-27 17:29:53 +0200 (Tue, 27 Sep 2011)" );
	script_cve_id( "CVE-2011-3579", "CVE-2011-3580" );
	script_bugtraq_id( 49753 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_name( "IceWarp Mail Server < 10.3.3 XML Entity Injection and Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/46135/" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/70026" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/70025" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/105320/TWSL2011-013.txt" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_icewarp_consolidation.sc" );
	script_mandatory_keys( "icewarp/mailserver/http/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to gain access to potentially
  sensitive information, and possibly cause denial-of-service conditions. Other attacks may also be possible." );
	script_tag( name: "affected", value: "IceWarp Mail Server 10.3.2 and prior." );
	script_tag( name: "solution", value: "Upgrade to IceWarp Mail Server 10.3.3 or later." );
	script_tag( name: "summary", value: "The host is running IceWarp Mail Server and is prone to xml entity injection
  and information disclosure vulnerability." );
	script_tag( name: "insight", value: "The flaws are due to:

  - Certain input passed via SOAP messages to 'server/webmail.php' is not properly verified before being used. This
  can be exploited to disclose the contents of arbitrary files.

  - An unspecified script, which calls the 'phpinfo()' function, is stored with insecure permissions inside the web
  root. This can be exploited to gain knowledge of sensitive information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!icewarp = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: icewarp, test_version: "10.3.3" )){
	report = report_fixed_ver( installed_version: icewarp, fixed_version: "10.3.3" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

