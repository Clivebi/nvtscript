CPE = "cpe:/a:cisco:asa";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805760" );
	script_version( "2019-07-05T09:29:25+0000" );
	script_cve_id( "CVE-2015-4458" );
	script_bugtraq_id( 75918 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-07-05 09:29:25 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-10-07 18:52:56 +0530 (Wed, 07 Oct 2015)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Cisco ASA Unauthorized Modification Vulnerability" );
	script_tag( name: "summary", value: "This host has Cisco ASA
  and is prone to unauthorized modification vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to insufficient checking
  of the MAC on TLS packets by the Cavium Networks cryptographic module used by
  an affected device." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to modify the contents of an encrypted TLS packet in transit from an
  affected device." );
	script_tag( name: "affected", value: "Cisco ASA 9.1(5.21)" );
	script_tag( name: "solution", value: "Apply the appropriate updates from Cisco." );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/viewAlert.x?alertId=39919" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "CISCO" );
	script_dependencies( "gb_cisco_asa_version.sc", "gb_cisco_asa_version_snmp.sc" );
	script_mandatory_keys( "cisco_asa/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
compver = ereg_replace( string: version, pattern: "\\(([0-9.]+)\\)", replace: ".\\1" );
if(version_is_equal( version: compver, test_version: "9.1.5.21" )){
	report = "Installed Version: " + compver + "\nFixed Version: Apply the appropriate updates from Cisco. \n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

