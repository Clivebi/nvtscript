CPE = "cpe:/a:cisco:asa";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806690" );
	script_version( "2020-03-04T09:29:37+0000" );
	script_cve_id( "CVE-2016-1312" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2020-03-04 09:29:37 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2016-03-22 12:49:04 +0530 (Tue, 22 Mar 2016)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Cisco ASA 5500 Devices Denial of Service Vulnerability - Mar16" );
	script_tag( name: "summary", value: "This host is running Cisco ASA 5500 device
  which is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an error in the HTTPS
  inspection engine of the Cisco ASA Content Security and Control Security Services
  Module (CSC-SSM) which improperly handles HTTPS packets transiting through the
  affected system." );
	script_tag( name: "impact", value: "Successful exploitation allows the attacker
  to cause exhaustion of available memory, system instability, and a reload of
  the affected system." );
	script_tag( name: "affected", value: "Cisco ASA 5500-X Series Firewalls with
  software version 6.6.x prior to 6.6.1164.0

  - ---
  NOTE:Cisco ASA 5500-X Series Firewalls with version 6.6.1157.0 is not vulnerable

  - ---" );
	script_tag( name: "solution", value: "Upgrade to the software version 6.6.1164.0
  or later. For more details" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://bst.cloudapps.cisco.com/bugsearch/bug/CSCue76147" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160309-csc" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CISCO" );
	script_dependencies( "gb_cisco_asa_version.sc" );
	script_mandatory_keys( "cisco_asa/version", "cisco_asa/model" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
model = get_kb_item( "cisco_asa/model" );
if(!model || !IsMatchRegexp( toupper( model ), "^ASA55[0-9][0-9]" )){
	exit( 0 );
}
if(!cisVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
cisVer = ereg_replace( string: cisVer, pattern: "\\(([0-9.]+)\\)", replace: ".\\1" );
if(IsMatchRegexp( cisVer, "^(6.6)" )){
	if(version_is_equal( version: cisVer, test_version: "6.6.1157.0" )){
		exit( 0 );
	}
	if(version_is_less( version: cisVer, test_version: "6.6.1164.0" )){
		report = report_fixed_ver( installed_version: cisVer, fixed_version: "6.6.1164.0" );
		security_message( data: report );
		exit( 0 );
	}
}

