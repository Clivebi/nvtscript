CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.101105" );
	script_version( "2021-09-14T09:46:07+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 09:46:07 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-24 07:49:31 +0200 (Mon, 24 Aug 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-2855" );
	script_name( "Squid < 3.1.4 External Auth Header Parser DoS Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_xref( name: "URL", value: "http://www.squid-cache.org/bugs/show_bug.cgi?id=2704" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2009/08/03/3" );
	script_xref( name: "URL", value: "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=534982" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to cause a
  denial of service via a crafted auth header with certain comma delimiters that trigger an infinite
  loop of calls to the strcspn function." );
	script_tag( name: "affected", value: "Squid version 2.7.x." );
	script_tag( name: "insight", value: "The flaw is due to error in 'strListGetItem()' function within
  'src/HttpHeaderTools.c'." );
	script_tag( name: "solution", value: "Update to version 3.1.4 or later." );
	script_tag( name: "summary", value: "Squid is prone to multiple denial of service (DoS)
  vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(IsMatchRegexp( vers, "^2\\.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.1.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

