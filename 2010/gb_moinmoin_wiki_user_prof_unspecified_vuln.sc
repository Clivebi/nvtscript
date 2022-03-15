CPE = "cpe:/a:moinmo:moinmoin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800172" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_bugtraq_id( 38023 );
	script_cve_id( "CVE-2010-0669" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "MoinMoin Wiki User Profile Unspecified Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_moinmoin_wiki_detect.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "moinmoinWiki/installed" );
	script_xref( name: "URL", value: "http://moinmo.in/SecurityFixes" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/38444" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2010/02/21/2" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2010/02/15/2" );
	script_tag( name: "impact", value: "Impact is currently unknown." );
	script_tag( name: "affected", value: "MoinMoin Wiki version before 1.8.7 and 1.9 before 1.9.2 on all platforms." );
	script_tag( name: "insight", value: "An unspecified error exists in MoinMoin Wiki related to sanitization of
  user profiles." );
	script_tag( name: "solution", value: "Upgrade to MoinMoin Wiki 1.8.7 or 1.9.2." );
	script_tag( name: "summary", value: "This host is running MoinMoin Wiki and is prone to unspecified
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
if(version_is_less( version: vers, test_version: "1.8.7" ) || version_in_range( version: vers, test_version: "1.9", test_version2: "1.9.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.8.7/1.9.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

