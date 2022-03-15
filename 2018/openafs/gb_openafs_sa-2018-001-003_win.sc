if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112379" );
	script_version( "2021-09-29T12:07:39+0000" );
	script_cve_id( "CVE-2018-16947", "CVE-2018-16948", "CVE-2018-16949" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-29 12:07:39 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-09-17 14:02:22 +0200 (Mon, 17 Sep 2018)" );
	script_name( "OpenAFS < 1.6.22.4, 1.8.x through 1.8.1.1 Multiple Vulnerabilities - Windows" );
	script_tag( name: "summary", value: "OpenAFS is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - The backup tape controller (butc) process accepts incoming RPCs but does not require (or allow for)
  authentication of those RPCs. Handling those RPCs results in operations being performed with administrator credentials,
  including dumping/restoring volume contents and manipulating the backup database.
  For example, an unauthenticated attacker can replace any volume's content with arbitrary data. (CVE-2018-16947)

  - Several RPC server routines did not fully initialize their output variables before returning,
  leaking memory contents from both the stack and the heap. Because the OpenAFS cache manager functions
  as an Rx server for the AFSCB service, clients are also susceptible to information leakage.
  For example, RXAFSCB_TellMeAboutYourself leaks kernel memory and KAM_ListEntry leaks kaserver memory. (CVE-2018-16948)

  - Several data types used as RPC input variables were implemented as unbounded array types,
  limited only by the inherent 32-bit length field to 4 GB. An unauthenticated attacker could send,
  or claim to send, large input values and consume server resources waiting for those inputs,
  denying service to other valid connections. (CVE-2018-16949)" );
	script_tag( name: "impact", value: "These issues cause various impact, the worst being that an unauthenticated, anonymous
  attacker can create volume dumps with contents of their own choosing, create and restore (potentially modified) backup
  database contents, and restore volumes from those modified backup database.

  For more information refer to the security advisories provided by the vendor." );
	script_tag( name: "affected", value: "OpenAFS before 1.6.23 and 1.8.x before 1.8.2." );
	script_tag( name: "solution", value: "Update to OpenAFS version 1.6.23 or 1.8.2 respectively." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.openafs.org/pages/security/OPENAFS-SA-2018-001.txt" );
	script_xref( name: "URL", value: "http://www.openafs.org/pages/security/OPENAFS-SA-2018-002.txt" );
	script_xref( name: "URL", value: "http://www.openafs.org/pages/security/OPENAFS-SA-2018-003.txt" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "gb_openafs_detect.sc" );
	script_mandatory_keys( "OpenAFS/Win/Installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
CPE = "cpe:/a:openafs:openafs";
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: vers, test_version: "1.6.23" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.6.23", install_path: path );
	security_message( data: report );
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "1.8.0", test_version2: "1.8.1.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.8.2", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

