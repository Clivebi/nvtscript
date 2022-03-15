CPE = "cpe:/a:moinmo:moinmoin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801306" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2010-1238" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-04-13 16:55:19 +0200 (Tue, 13 Apr 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "MoinMoin Wiki Security Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_moinmoin_wiki_detect.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "moinmoinWiki/installed" );
	script_xref( name: "URL", value: "http://moinmo.in/SecurityFixes" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2010/dsa-2024" );
	script_xref( name: "URL", value: "http://comments.gmane.org/gmane.comp.security.oss.general/2773" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to bypass intended access
  restrictions by requesting an item." );
	script_tag( name: "affected", value: "MoinMoin Wiki version 1.7.1 and prior" );
	script_tag( name: "insight", value: "The flaw exists due to an error in handling of 'textcha' protection mechanism,
  which can be bypassed by modifying the 'textcha-question' and 'textcha-answer fields'
  to have empty values." );
	script_tag( name: "solution", value: "Upgrade MoinMoin Wiki to 1.7.1-3 or later." );
	script_tag( name: "summary", value: "This host is running MoinMoin Wiki and is prone to a security bypass
  vulnerability." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: vers, test_version: "1.7.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.7.1-3" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

