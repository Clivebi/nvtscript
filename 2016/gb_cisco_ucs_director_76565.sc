CPE = "cpe:/a:cisco:ucs_director";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105577" );
	script_version( "2020-09-23T10:02:17+0000" );
	script_tag( name: "last_modification", value: "2020-09-23 10:02:17 +0000 (Wed, 23 Sep 2020)" );
	script_tag( name: "creation_date", value: "2016-03-17 16:14:29 +0100 (Thu, 17 Mar 2016)" );
	script_tag( name: "cvss_base", value: "9.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:C/A:C" );
	script_bugtraq_id( 76565 );
	script_cve_id( "CVE-2015-6259" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "UCS Director Arbitrary File Overwrite Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_ucs_director_consolidation.sc" );
	script_mandatory_keys( "cisco/ucs_director/detected" );
	script_tag( name: "summary", value: "Cisco UCS Director is prone to a vulnerability that may allow attackers to over
  write arbitrary files." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is due to incomplete input sanitization on specific JSP pages." );
	script_tag( name: "impact", value: "Successful exploits may allow an attacker to overwrite arbitrary system files,
  resulting in system instability or a denial of service condition." );
	script_tag( name: "affected", value: "Cisco UCS Director prior to version 5.2.0.1." );
	script_tag( name: "solution", value: "Update to 5.2.0.1 or newer." );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150902-cimcs" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "5.2.0.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.2.0.1" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

