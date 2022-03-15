if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902179" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)" );
	script_cve_id( "CVE-2010-1629" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Phorum Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://www.facebook.com/note.php?note_id=371190874581" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2010/05/16/2" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2010/05/18/11" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "phorum_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phorum/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary code in
  the context of an application." );
	script_tag( name: "affected", value: "Phorum version prior to 5.2.15." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade Phorum to 5.2.15 or later." );
	script_tag( name: "summary", value: "This host is running Phorum and is prone to cross-site
  scripting vulnerability." );
	script_tag( name: "insight", value: "The flaw is due to error in handling email address.

  NOTE: Further information is not available." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
phorumPort = http_get_port( default: 80 );
phorumVer = get_kb_item( NASLString( "www/", phorumPort, "/phorum" ) );
phorumVer = eregmatch( pattern: "^(.+) under (/.*)$", string: phorumVer );
if(!phorumVer[1]){
	exit( 0 );
}
if(version_is_less( version: phorumVer[1], test_version: "5.2.15" )){
	report = report_fixed_ver( installed_version: phorumVer[1], fixed_version: "5.2.15" );
	security_message( port: phorumPort, data: report );
}

