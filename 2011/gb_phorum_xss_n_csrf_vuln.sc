if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802160" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)" );
	script_cve_id( "CVE-2011-3381", "CVE-2011-3382" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Phorum Cross-Site Scripting and Cross-site request forgery Vulnerabilities" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN71435255/index.html" );
	script_xref( name: "URL", value: "http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000068.html" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "phorum_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phorum/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary code in
  the context of an application." );
	script_tag( name: "affected", value: "Phorum version prior to 5.2.16." );
	script_tag( name: "insight", value: "The flaws are due to unspecified errors in the application." );
	script_tag( name: "solution", value: "Upgrade Phorum to 5.2.16 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is running Phorum and is prone to cross-site scripting
  and cross-site request forgery vulnerabilities." );
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
if(version_is_less( version: phorumVer, test_version: "5.2.16" )){
	report = report_fixed_ver( installed_version: phorumVer, fixed_version: "5.2.16" );
	security_message( port: phorumPort, data: report );
}

