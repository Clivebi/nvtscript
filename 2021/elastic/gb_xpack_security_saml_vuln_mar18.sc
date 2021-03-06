CPE = "cpe:/a:elastic:x-pack";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117171" );
	script_version( "2021-08-17T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-01-19 14:15:51 +0000 (Tue, 19 Jan 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:40:00 +0000 (Wed, 09 Oct 2019)" );
	script_cve_id( "CVE-2018-3822" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Elastic X-Pack Security SAML Vulnerability (ESA-2018-07)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_elastic_kibana_detect_http.sc" );
	script_mandatory_keys( "elastic/kibana/x-pack/detected" );
	script_tag( name: "summary", value: "Elastic X-Pack Security is prone to a vulnerability in the
  SAML implementation." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "X-Pack Security is vulnerable to a user impersonation attack
  via incorrect XML canonicalization and DOM traversal." );
	script_tag( name: "impact", value: "An attacker might have been able to impersonate a legitimate user if
  the SAML Identity Provider allows for self registration with arbitrary identifiers and the attacker
  can register an account with an identifier that shares a suffix with a legitimate account. Both of
  those conditions must be true in order to exploit this flaw." );
	script_tag( name: "affected", value: "X-Pack Security 6.2.0, 6.2.1, and 6.2.2." );
	script_tag( name: "solution", value: "Update to Elasticsearch version 6.2.3 or later." );
	script_xref( name: "URL", value: "https://discuss.elastic.co/t/elastic-stack-6-2-3-security-update/124848" );
	script_xref( name: "URL", value: "https://www.elastic.co/community/security" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "6.2.0", test_version2: "6.2.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.2.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

