CPE = "cpe:/a:elastic:logstash";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107278" );
	script_version( "2021-05-28T06:00:18+0200" );
	script_bugtraq_id( 76015 );
	script_cve_id( "CVE-2015-5378" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-05-28 06:00:18 +0200 (Fri, 28 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-17 15:48:00 +0000 (Mon, 17 Jun 2019)" );
	script_tag( name: "creation_date", value: "2018-01-31 14:18:58 +0100 (Wed, 31 Jan 2018)" );
	script_name( "Elastic Logstash 'CVE-2015-5378' Man in the Middle Security Bypass Vulnerability" );
	script_tag( name: "summary", value: "Elastic Logstash is prone to security-bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to the usage of Lumberjack input
  (in combination with Logstash Forwarder agent)" );
	script_tag( name: "impact", value: "Successfully exploiting these issues may allow attackers
  to perform unauthorized actions by conducting a man-in-the-middle attack. This may lead
  to other attacks." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "affected", value: "Elastic Logstash version prior to
  1.5.3 or 1.4.4." );
	script_tag( name: "solution", value: "Users should update to 1.5.3 or 1.4.4. Users that do not
  want to upgrade can address the vulnerability by disabling the Lumberjack input." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.elastic.co/community/security/" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/76015/" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_elastic_elasticsearch_detect_http.sc" );
	script_mandatory_keys( "elastic/logstash/detected" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^1\\.4\\." )){
	if(version_is_less( version: version, test_version: "1.4.3" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "1.4.3" );
	}
}
if(IsMatchRegexp( version, "^1\\.5\\." )){
	if(version_is_less( version: version, test_version: "1.5.3" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "1.5.3" );
	}
}
if(report != ""){
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

