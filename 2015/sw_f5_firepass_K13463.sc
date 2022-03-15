CPE = "cpe:/h:f5:firepass";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111017" );
	script_version( "2021-05-26T13:59:24+0000" );
	script_tag( name: "last_modification", value: "2021-05-26 13:59:24 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2015-04-17 08:00:00 +0100 (Fri, 17 Apr 2015)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2012-1777" );
	script_name( "F5 FirePass SQL injection vulnerability CVE-2012-1777" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_f5_firepass_http_detect.sc" );
	script_mandatory_keys( "f5/firepass/detected" );
	script_tag( name: "summary", value: "F5 FirePass is prone to an SQL injection vulnerability." );
	script_tag( name: "insight", value: "An SQL injection in my.activation.php3 allows remote attackers
  to execute arbitrary SQL commands via the state parameter." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "F5 FirePass version 6.0.0 through 6.1.0 and 7.0.0." );
	script_tag( name: "solution", value: "The vendor has released a Hotfix HF-377712-1 listened in the
  referenced advisory." );
	script_xref( name: "URL", value: "https://support.f5.com/csp/article/K13463" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/111276/F5-FirePass-SSL-VPN-6.x-7.x-SQL-Injection.html" );
	script_xref( name: "URL", value: "https://www.sec-consult.com/files/20120328-0_F5_FirePass_SSL_VPN_unauthenticated_remote_root_v1.0.txt" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
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
if(version_in_range( version: vers, test_version: "6.0.0", test_version2: "6.1.0" ) || version_is_equal( version: vers, test_version: "7.0.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "6.1.0 HF-377712-1/7.0.0 HF-377712-1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

