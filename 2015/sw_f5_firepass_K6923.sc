CPE = "cpe:/h:f5:firepass";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111016" );
	script_version( "2021-05-26T13:59:24+0000" );
	script_tag( name: "last_modification", value: "2021-05-26 13:59:24 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2015-04-17 08:00:00 +0100 (Fri, 17 Apr 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2007-0195" );
	script_bugtraq_id( 21957 );
	script_name( "F5 FirePass Multiple Input Validation Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_f5_firepass_http_detect.sc" );
	script_mandatory_keys( "f5/firepass/detected" );
	script_tag( name: "summary", value: "F5 FirePass is prone to multiple input-validation
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The device fails to sufficiently sanitize user-supplied input.
  These issues include information-disclosure, security bypass, and cross-site scripting
  vulnerabilities." );
	script_tag( name: "impact", value: "An attacker can exploit these issues to bypass security
  restrictions, to view sensitive information, and to steal cookie-based authentication credentials.
  This may allow the attacker to compromise the application and the underlying system. Other attacks
  are also possible." );
	script_tag( name: "affected", value: "F5 FirePass 5.4.0 through 5.5.1 and 6.0.0." );
	script_tag( name: "solution", value: "The vendor has released updates listened in the referenced
  advisory." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/21957" );
	script_xref( name: "URL", value: "https://support.f5.com/csp/article/K6923" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
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
if(version_in_range( version: vers, test_version: "5.4.0", test_version2: "5.5.1" ) || version_is_equal( version: vers, test_version: "6.0.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.5.2/6.0.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

