if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805266" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-0410", "CVE-2015-0408", "CVE-2015-0407", "CVE-2015-0395", "CVE-2015-0383", "CVE-2014-6593", "CVE-2014-6591", "CVE-2014-6585" );
	script_bugtraq_id( 72165, 72140, 72162, 72142, 72155, 72169, 72175, 72173 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-02-02 14:08:03 +0530 (Mon, 02 Feb 2015)" );
	script_name( "Oracle Java SE JRE Multiple Unspecified Vulnerabilities-04 Feb 2015 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Oracle Java SE
  JRE and is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple unspecified flaws exist due to:

  - An infinite loop in the DER decoder that is triggered when handling negative
  length values.

  - An error in the RMI component's transport implementation related to incorrect
  context class loader use.

  - An error in the Swing component's file chooser implementation.

  - An error in vm/memory/referenceProcessor.cpp related to handling of phantom
  object references in the Hotspot JVM garbage collector.

  - An error in the Hotspot JVM related to insecure handling of temporary
  performance data files.

  - An error in the JSSE component related to improper ChangeCipherSpec tracking
  during SSL/TLS handshakes.

  - Two out-of-bounds read errors in the layout component that is triggered when
  parsing fonts." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to conduct a denial of service attack, man-in-the-middle attack, potentially
  disclose memory contents, remove or overwrite arbitrary files on the system,
  disclose certain directory information, bypass sandbox restrictions and
  potentially execute arbitrary code." );
	script_tag( name: "affected", value: "Oracle Java SE 5 update 75 and prior, 6
  update 85 and prior, 7 update 72 and prior, and 8 update 25 and prior on
  Windows." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/62215" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_portable_win.sc" );
	script_mandatory_keys( "Sun/Java/JRE/Win/Ver" );
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
if(IsMatchRegexp( vers, "^1\\.[5-8]" )){
	if(version_in_range( version: vers, test_version: "1.5.0", test_version2: "1.5.0.75" ) || version_in_range( version: vers, test_version: "1.6.0", test_version2: "1.6.0.85" ) || version_in_range( version: vers, test_version: "1.7.0", test_version2: "1.7.0.72" ) || version_in_range( version: vers, test_version: "1.8.0", test_version2: "1.8.0.25" )){
		report = "Installed version: " + vers + "\n" + "Fixed version:     " + "Apply the patch" + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

