CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806518" );
	script_version( "$Revision: 11872 $" );
	script_cve_id( "CVE-2015-5400" );
	script_bugtraq_id( 75553 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-10-28 17:35:29 +0530 (Wed, 28 Oct 2015)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Squid 'cache_peer' Security Bypass Vulnerability" );
	script_tag( name: "summary", value: "This host is running Squid and is prone
  to access bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to improper handling of
  CONNECT method peer responses when configured with cache_peer." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to bypass security in an explicit gateway proxy." );
	script_tag( name: "affected", value: "Squid version 3.5.5 and earlier" );
	script_tag( name: "solution", value: "Upgrade to version 3.5.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Advisories/SQUID-2015_2.txt" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2015/07/09/12" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_require_ports( "Services/www", 3128, 8080 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!squidPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!squidVer = get_app_version( cpe: CPE, port: squidPort )){
	exit( 0 );
}
if(version_is_less( version: squidVer, test_version: "3.5.6" )){
	report = "Installed version: " + squidVer + "\n" + "Fixed version:     3.5.6\n";
	security_message( data: report, port: squidPort );
	exit( 0 );
}
exit( 99 );

