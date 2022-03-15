if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800565" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-05-07 14:39:04 +0200 (Thu, 07 May 2009)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-6747" );
	script_bugtraq_id( 29679 );
	script_name( "dotProject Privilege Escalation Vulnerability" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/378282.php" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/43019" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Privilege escalation" );
	script_dependencies( "gb_dotproject_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "dotproject/detected" );
	script_tag( name: "impact", value: "Attackers can exploit this issue via specially crafted HTTP request to
  certain administrative pages to gain administrative privileges on the affected system." );
	script_tag( name: "affected", value: "dotProject prior to version 2.1.2." );
	script_tag( name: "insight", value: "The flaw is due to improper restrictions on access to certain
  administrative pages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to version 2.1.2." );
	script_tag( name: "summary", value: "The host is installed with dotProject and is prone to a Privilege
  Escalation vulnerability." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
appPort = http_get_port( default: 80 );
dotVer = get_kb_item( "www/" + appPort + "/dotProject" );
dotVer = eregmatch( pattern: "^(.+) under (/.*)$", string: dotVer );
if(dotVer[1] == NULL){
	exit( 0 );
}
if(version_is_less( version: dotVer[1], test_version: "2.1.2" )){
	report = report_fixed_ver( installed_version: dotVer[1], fixed_version: "2.1.2" );
	security_message( port: appPort, data: report );
	exit( 0 );
}
exit( 99 );

