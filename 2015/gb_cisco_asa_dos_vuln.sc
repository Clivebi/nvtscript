CPE = "cpe:/a:cisco:asa";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805759" );
	script_version( "2019-07-05T09:54:18+0000" );
	script_cve_id( "CVE-2015-4241" );
	script_bugtraq_id( 75581 );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2019-07-05 09:54:18 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-10-07 18:52:56 +0530 (Wed, 07 Oct 2015)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Cisco ASA DoS Vulnerability" );
	script_tag( name: "summary", value: "This host has Cisco ASA
  and is prone to dos vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to improper handling of
  OSPFv2 packets by an affected system." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct denial of service attack." );
	script_tag( name: "affected", value: "Cisco ASA 9.3.2" );
	script_tag( name: "solution", value: "Apply the patch from Cisco." );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/viewAlert.x?alertId=39641" );
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
if(version_is_equal( version: compver, test_version: "9.3.2" )){
	report = "Installed Version: " + compver + "\nFixed Version: Apply the appropriate updates from Cisco. \n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

