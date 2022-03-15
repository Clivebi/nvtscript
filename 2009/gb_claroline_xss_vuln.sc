if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800628" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-1907" );
	script_bugtraq_id( 34883 );
	script_name( "Claroline 'notfound.php' Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35019" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/50404" );
	script_xref( name: "URL", value: "http://gsasec.blogspot.com/2009/05/claroline-v1811-cross-site-scripting.html" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_claroline_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "claroline/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to compromise the application,
  access or modify data, or exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "Claroline Version 1.8.11 and prior." );
	script_tag( name: "insight", value: "The flaw is due to:

  - error in 'claroline/linker/notfound.php' which is not properly sanitising
  input data passed via the 'Referer' header, before being returned to the user.

  - error in 'group/group.php' which is not properly sanitising input data
  passed to the 'sort' parameter, before being used in an SQL query." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to the version version 1.8.12 or later." );
	script_tag( name: "summary", value: "The host is running Claroline and is prone to SQL Injection
  Vulnerability." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
clarolinPort = http_get_port( default: 80 );
clarolineVer = get_kb_item( "www/" + clarolinPort + "/Claroline" );
if(!clarolineVer){
	exit( 0 );
}
clarolineVer = eregmatch( pattern: "^(.+) under (/.*)$", string: clarolineVer );
if(clarolineVer[1] != NULL){
	if(version_is_less_equal( version: clarolineVer[1], test_version: "1.8.11" )){
		report = report_fixed_ver( installed_version: clarolineVer[1], vulnerable_range: "Less than or equal to 1.8.11" );
		security_message( port: clarolinPort, data: report );
	}
}

