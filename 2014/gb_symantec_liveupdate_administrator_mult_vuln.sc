CPE = "cpe:/a:symantec:liveupdate_administrator";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804359" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-1644", "CVE-2014-1645" );
	script_bugtraq_id( 66399, 66400 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-04-03 15:36:12 +0530 (Thu, 03 Apr 2014)" );
	script_name( "Symantec LiveUpdate Administrator Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "The host is installed with Symantec LiveUpdate Administrator and is prone to
multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Improper restrictions on access to the 'lua/forcepasswd.do' script.

  - Improper sanitization of input passed to 'lua/forcepasswd.do' and
'loginforgotpwd' scripts." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to bypass certain security
restrictions and inject or manipulate SQL queries in the back-end database,
allowing for the manipulation or disclosure of arbitrary data." );
	script_tag( name: "affected", value: "Symantec LiveUpdate Administrator before version 2.x before 2.3.2.110" );
	script_tag( name: "solution", value: "Upgrade to Symantec LiveUpdate Administrator version 2.3.2.110 or later." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57659" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1029972" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/125925" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2014-03/0172.html" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_symantec_liveupdate_administrator_detect.sc" );
	script_mandatory_keys( "Symantec/LUA/Version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!luaPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!luaVer = get_app_version( cpe: CPE, port: luaPort )){
	exit( 0 );
}
if(version_in_range( version: luaVer, test_version: "2.0", test_version2: "2.3.2.109" )){
	report = report_fixed_ver( installed_version: luaVer, vulnerable_range: "2.0 - 2.3.2.109" );
	security_message( port: luaPort, data: report );
	exit( 0 );
}

