CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806107" );
	script_version( "2019-05-20T11:12:48+0000" );
	script_cve_id( "CVE-2014-0128" );
	script_bugtraq_id( 66112 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)" );
	script_tag( name: "creation_date", value: "2015-09-08 16:31:16 +0530 (Tue, 08 Sep 2015)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Squid SSL-Bump HTTPS Requests Processing Denial of Service Vulnerability" );
	script_tag( name: "summary", value: "This host is running Squid and is prone
  to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Due to incorrect state management Squid is vulnerable to a denial
  of service attack when processing certain HTTPS requests." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial of service." );
	script_tag( name: "affected", value: "Squid 3.1 -> 3.3.11,
  Squid 3.4 -> 3.4.3" );
	script_tag( name: "solution", value: "Apply the patch or upgrade to version
  Squid 3.4.4, 3.3.11 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Advisories/SQUID-2014_1.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_require_ports( "Services/www", 3128, 8080 );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Advisories/SQUID-2014_2.txt" );
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
if(!IsMatchRegexp( squidVer, "^3\\." )){
	exit( 99 );
}
if( version_in_range( version: squidVer, test_version: "3.1", test_version2: "3.3.11" ) ){
	VULN = TRUE;
	Fix = "3.3.12";
}
else {
	if(version_in_range( version: squidVer, test_version: "3.4", test_version2: "3.4.3" )){
		VULN = TRUE;
		Fix = "3.4.4";
	}
}
if(VULN){
	report = "Installed version: " + squidVer + "\n" + "Fixed version:     " + Fix + "\n";
	security_message( data: report, port: squidPort );
	exit( 0 );
}

