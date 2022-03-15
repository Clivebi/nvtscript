CPE = "cpe:/a:serv-u:serv-u";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100767" );
	script_version( "2019-06-24T07:41:01+0000" );
	script_tag( name: "last_modification", value: "2019-06-24 07:41:01 +0000 (Mon, 24 Jun 2019)" );
	script_tag( name: "creation_date", value: "2010-08-31 14:30:50 +0200 (Tue, 31 Aug 2010)" );
	script_bugtraq_id( 42523 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Serv-U Denial of Service and Security Bypass Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/42523" );
	script_xref( name: "URL", value: "http://www.serv-u.com/releasenotes/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "FTP" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_solarwinds_serv-u_consolidation.sc" );
	script_mandatory_keys( "solarwinds/servu/detected" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "Serv-U is prone to denial-of-service and security-bypass
  vulnerabilities." );
	script_tag( name: "impact", value: "Exploiting these issues can allow attackers to create directories
  without having sufficient permissions, or crash the affected application, resulting in denial-of-service conditions." );
	script_tag( name: "affected", value: "Versions prior to Serv-U 10.2.0.0 are vulnerable." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "10.2.0.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.2.0.0" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

