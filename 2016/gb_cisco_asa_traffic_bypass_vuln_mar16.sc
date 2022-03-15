CPE = "cpe:/a:cisco:asa";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807093" );
	script_version( "2020-03-04T09:29:37+0000" );
	script_cve_id( "CVE-2015-6423" );
	script_bugtraq_id( 80249 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-03-04 09:29:37 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2016-03-02 15:10:26 +0530 (Wed, 02 Mar 2016)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Cisco ASA Non-DCERPC Traffic Bypass Vulnerability March16" );
	script_tag( name: "summary", value: "This host is running Cisco ASA Software and
  is prone to traffic bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an internal access
  control list (ACL), which is used to allow DCERPC traffic but is incorrectly
  programmed to allow all traffic types and not restricted to DCERPC
  TCP port 135." );
	script_tag( name: "impact", value: "Successful exploitation allows the attacker
  to access hosts that should normally be restricted through the ASA." );
	script_tag( name: "affected", value: "Cisco ASA Software versions 9.4.1 up to
  9.5.1." );
	script_tag( name: "solution", value: "Upgrade to software updates available
  from the advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160111-asa" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CISCO" );
	script_dependencies( "gb_cisco_asa_version.sc", "gb_cisco_asa_version_snmp.sc" );
	script_mandatory_keys( "cisco_asa/version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!cisVer = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
cisVer = ereg_replace( string: cisVer, pattern: "\\(([0-9.]+)\\)", replace: ".\\1" );
if(IsMatchRegexp( cisVer, "^(9\\.(4|5))" )){
	if(version_in_range( version: cisVer, test_version: "9.4.1", test_version2: "9.5.1" )){
		report = report_fixed_ver( installed_version: cisVer, fixed_version: "Apply the software updates" );
		security_message( data: report );
		exit( 0 );
	}
}

