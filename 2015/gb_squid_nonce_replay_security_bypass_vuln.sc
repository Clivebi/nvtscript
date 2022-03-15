CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806902" );
	script_version( "2019-07-05T10:41:31+0000" );
	script_cve_id( "CVE-2014-9749" );
	script_bugtraq_id( 77040 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-07-05 10:41:31 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-12-23 13:34:49 +0530 (Wed, 23 Dec 2015)" );
	script_name( "Squid Nonce Replay Security Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_require_ports( "Services/www", 3128, 8080 );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2015/10/11/4" );
	script_xref( name: "URL", value: "http://bugs.squid-cache.org/show_bug.cgi?id=4066" );
	script_tag( name: "summary", value: "This host is running Squid and is prone
  to security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to some unspecified error
  in digest_authentication." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  disabled user or users with changed password to access the squid service with
  old credentials." );
	script_tag( name: "affected", value: "Squid versions 3.4.4 through 3.4.11 and 3.5.0.1 through 3.5.1" );
	script_tag( name: "solution", value: "Upgrade to Squid 3.4.12 or 3.5.2
  or later." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(IsMatchRegexp( !squidVer, "^3\\." )){
	exit( 0 );
}
if( version_in_range( version: squidVer, test_version: "3.4.4", test_version2: "3.4.11" ) ){
	VULN = TRUE;
	Fix = "3.4.12";
}
else {
	if(version_in_range( version: squidVer, test_version: "3.5.0.1", test_version2: "3.5.1" )){
		VULN = TRUE;
		Fix = "3.5.2";
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: squidVer, fixed_version: Fix );
	security_message( data: report, port: squidPort );
	exit( 0 );
}

