CPE = "cpe:/a:openafs:openafs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808073" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2015-7763", "CVE-2015-7762" );
	script_bugtraq_id( 77407 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-06-08 13:06:35 +0530 (Wed, 08 Jun 2016)" );
	script_name( "OpenAFS Multiple Information Disclosure Vulnerabilities (Windows)" );
	script_tag( name: "summary", value: "This host is installed with OpenAFS and
  is prone to multiple information disclosure vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - 'rx/rx.c' in OpenAFS does not properly initialize padding at the end of an Rx
    acknowledgement (ACK) packet.

  - 'rx/rx.c' in OpenAFS does not properly initialize the padding of a data structure
    when constructing an Rx acknowledgement (ACK) packet." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to obtain sensitive information by conducting a replay
  attack or sniffing the network." );
	script_tag( name: "affected", value: "OpenAFS version prior to 1.4.16 and 1.5.75
  through 1.5.78 and 1.6.X prior to 1.6.15, 1.7.x prior to 1.7.33 on Windows." );
	script_tag( name: "solution", value: "Update to OpenAFS version 1.7.33 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.openafs.org/dl/openafs/1.6.15/RELNOTES-1.6.15" );
	script_xref( name: "URL", value: "https://www.openafs.org/pages/security/OPENAFS-SA-2015-007.txt" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_openafs_detect.sc" );
	script_mandatory_keys( "OpenAFS/Win/Installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!afsVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: afsVer, test_version: "1.4.16" ) || version_in_range( version: afsVer, test_version: "1.5.75", test_version2: "1.5.78" ) || version_in_range( version: afsVer, test_version: "1.6.0", test_version2: "1.6.14" ) || version_in_range( version: afsVer, test_version: "1.7.0", test_version2: "1.7.32" )){
	report = report_fixed_ver( installed_version: afsVer, fixed_version: "1.7.33" );
	security_message( data: report );
	exit( 0 );
}

