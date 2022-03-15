CPE = "cpe:/a:process-one:ejabberd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100487" );
	script_version( "2020-06-10T03:16:09+0000" );
	script_tag( name: "last_modification", value: "2020-06-10 03:16:09 +0000 (Wed, 10 Jun 2020)" );
	script_tag( name: "creation_date", value: "2010-02-08 23:29:56 +0100 (Mon, 08 Feb 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2010-0305" );
	script_bugtraq_id( 38003 );
	script_name( "ejabberd 'client2server' Message Remote Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/38003" );
	script_xref( name: "URL", value: "https://support.process-one.net/browse/EJAB/fixforversion/10453" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_ejabberd_consolidation.sc" );
	script_mandatory_keys( "ejabberd/detected" );
	script_tag( name: "solution", value: "The vendor has released an update. Please see the references for details." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "ejabberd is prone to a denial-of-service vulnerability." );
	script_tag( name: "insight", value: "An attacker can exploit this issue to crash the affected application,
  denying service to legitimate users." );
	script_tag( name: "affected", value: "ejabberd prior to version 2.1.3." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "2.1.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.1.3" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

