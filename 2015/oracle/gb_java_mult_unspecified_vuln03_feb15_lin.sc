if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108401" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-0412", "CVE-2015-0406", "CVE-2015-0403", "CVE-2015-0400", "CVE-2014-6601", "CVE-2014-6587" );
	script_bugtraq_id( 72136, 72154, 72148, 72159, 72132, 72168 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-02-02 13:08:03 +0530 (Mon, 02 Feb 2015)" );
	script_name( "Oracle Java SE JRE Multiple Unspecified Vulnerabilities-03 Feb 2015 (Linux)" );
	script_tag( name: "summary", value: "The host is installed with Oracle Java SE
  JRE and is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple unspecified flaws exist due to:

  - An unspecified error in the JAX-WS component related to insufficient
  privilege checks.

  - Two unspecified errors in the Deployment component.

  - An unspecified error in the 'Libraries' component.

  - An error in vm/classfile/verifier.cpp script related to insufficient
  verification of invokespecial calls.

  - A NULL pointer dereference error in the MulticastSocket implementation." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to gain escalated privileges, conduct a denial of service attack, bypass
  sandbox restrictions and execute arbitrary code." );
	script_tag( name: "affected", value: "Oracle Java SE 6 update 85 and prior,
  7 update 72 and prior, and 8 update 25 and prior on Linux." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/62215" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_lin.sc" );
	script_mandatory_keys( "Sun/Java/JRE/Linux/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:oracle:jre",
	 "cpe:/a:sun:jre" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(IsMatchRegexp( vers, "^1\\.[6-8]" )){
	if(version_in_range( version: vers, test_version: "1.6.0", test_version2: "1.6.0.85" ) || version_in_range( version: vers, test_version: "1.7.0", test_version2: "1.7.0.72" ) || version_in_range( version: vers, test_version: "1.8.0", test_version2: "1.8.0.25" )){
		report = "Installed version: " + vers + "\n" + "Fixed version:     " + "Apply the patch" + "\n";
		security_message( data: report );
		exit( 0 );
	}
}
exit( 99 );

