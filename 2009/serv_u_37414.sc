CPE = "cpe:/a:serv-u:serv-u";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100410" );
	script_version( "2019-06-24T07:41:01+0000" );
	script_tag( name: "last_modification", value: "2019-06-24 07:41:01 +0000 (Mon, 24 Jun 2019)" );
	script_tag( name: "creation_date", value: "2009-12-21 12:36:27 +0100 (Mon, 21 Dec 2009)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_cve_id( "CVE-2009-4815" );
	script_bugtraq_id( 37414 );
	script_name( "Serv-U File Server User Directory Information Disclosure Vulnerability" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "FTP" );
	script_copyright( "This script is Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "gb_solarwinds_serv-u_consolidation.sc" );
	script_mandatory_keys( "solarwinds/servu/detected" );
	script_tag( name: "solution", value: "The vendor has released an update. Please see the references
  for details." );
	script_tag( name: "summary", value: "Serv-U File Server is prone to an unspecified information-disclosure
  vulnerability." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to harvest sensitive information that
  may lead to further attacks." );
	script_tag( name: "affected", value: "Versions prior to Serv-U File Server 9.2.0.1 are vulnerable." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37414" );
	script_xref( name: "URL", value: "http://www.serv-u.com/releasenotes/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "9.2.0.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.2.0.1" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

