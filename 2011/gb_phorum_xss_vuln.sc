if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802161" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)" );
	script_cve_id( "CVE-2011-3392" );
	script_bugtraq_id( 49347 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Phorum 'real_name' Parameter Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/45787" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/69456" );
	script_xref( name: "URL", value: "http://holisticinfosec.org/content/view/184/45/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "phorum_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phorum/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "Phorum version prior to 5.2.17." );
	script_tag( name: "insight", value: "The flaw is due to input passed via the 'real_name' parameter to the
  'control.php' script is not properly sanitised before being returned to the user." );
	script_tag( name: "solution", value: "Upgrade Phorum to 5.2.17 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is running Phorum and is prone to cross-site scripting
  vulnerability." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
phorumPort = http_get_port( default: 80 );
phorumVer = get_version_from_kb( port: phorumPort, app: "phorum" );
if(!phorumVer){
	exit( 0 );
}
if(version_is_less( version: phorumVer, test_version: "5.2.17" )){
	report = report_fixed_ver( installed_version: phorumVer, fixed_version: "5.2.17" );
	security_message( port: 0, data: report );
}

