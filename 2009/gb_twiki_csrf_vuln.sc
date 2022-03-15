CPE = "cpe:/a:twiki:twiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800400" );
	script_version( "$Revision: 12952 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-01-07 07:54:36 +0100 (Mon, 07 Jan 2019) $" );
	script_tag( name: "creation_date", value: "2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-1339" );
	script_name( "TWiki Cross-Site Request Forgery Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_twiki_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "twiki/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to gain administrative
  privileges on the target application and can cause CSRF attack." );
	script_tag( name: "affected", value: "TWiki version prior to 4.3.1" );
	script_tag( name: "insight", value: "Remote authenticated user can create a specially crafted image tag that,
  when viewed by the target user, will update pages on the target system with the privileges of the target user
  via HTTP requests." );
	script_tag( name: "solution", value: "Upgrade to version 4.3.1 or later." );
	script_tag( name: "summary", value: "The host is running TWiki and is prone to Cross-Site Request
  Forgery Vulnerability." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34880" );
	script_xref( name: "URL", value: "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=526258" );
	script_xref( name: "URL", value: "http://twiki.org/p/pub/Codev/SecurityAlert-CVE-2009-1339/TWiki-4.3.0-c-diff-cve-2009-1339.txt" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "4.3.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.3.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

