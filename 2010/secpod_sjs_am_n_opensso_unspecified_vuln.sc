if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902165" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-04-29 10:04:32 +0200 (Thu, 29 Apr 2010)" );
	script_cve_id( "CVE-2010-0894" );
	script_bugtraq_id( 39457 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_name( "Sun JS Access Manager And OpenSSO Unspecified Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_sun_opensso_detect.sc", "secpod_sjs_access_manager_detect.sc" );
	script_mandatory_keys( "JavaSysAccessManger_or_OracleOpenSSO/detected" );
	script_xref( name: "URL", value: "http://www.us-cert.gov/cas/techalerts/TA10-103B.html" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to affect confidentiality
  and integrity via unknown vectors." );
	script_tag( name: "affected", value: "Sun OpenSSO Enterprise version 8.0,

  Java System Access Manager version 7.1 and 7.0.2005Q4" );
	script_tag( name: "insight", value: "The flaw is due to unspecified errors in the application, allows remote
  attackers to affect confidentiality and integrity via unknown vectors." );
	script_tag( name: "summary", value: "The host is running Access Manager or OpenSSO and is prone to
  unspecified vulnerability." );
	script_tag( name: "solution", value: "Apply the security updates." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
am_port = http_get_port( default: 8080 );
amVer = get_kb_item( "www/" + am_port + "/Sun/JavaSysAccessManger" );
amVer = eregmatch( pattern: "^(.+) under (/.*)$", string: amVer );
if(IsMatchRegexp( amVer[1], "(7\\.1|7\\.0\\.2005Q4)" )){
	security_message( am_port );
	exit( 0 );
}
ssoVer = get_kb_item( "www/" + am_port + "/Sun/OpenSSO" );
ssoVer = eregmatch( pattern: "^(.+) under (/.*)$", string: ssoVer );
if(IsMatchRegexp( ssoVer[1], "^8\\.0" )){
	security_message( am_port );
}

