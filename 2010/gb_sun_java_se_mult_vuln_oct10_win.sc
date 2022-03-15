if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801530" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-10-28 11:50:37 +0200 (Thu, 28 Oct 2010)" );
	script_cve_id( "CVE-2010-3550", "CVE-2010-3551", "CVE-2010-3552", "CVE-2010-3553", "CVE-2010-3554", "CVE-2010-3555", "CVE-2010-3556", "CVE-2010-3557", "CVE-2010-3558", "CVE-2010-3559", "CVE-2010-3560", "CVE-2010-3561", "CVE-2010-3562", "CVE-2010-3563", "CVE-2010-3565", "CVE-2010-3566", "CVE-2010-3567", "CVE-2010-3568", "CVE-2010-3569", "CVE-2010-3570", "CVE-2010-3571", "CVE-2010-3572", "CVE-2010-3573", "CVE-2010-3574" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Oracle Java SE Multiple Vulnerabilities (Windows)" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/2660" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/javacpuoct2010-176258.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/java/javase/downloads/index-jsp-138363.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_portable_win.sc" );
	script_mandatory_keys( "Sun/Java/JDK_or_JRE/Win/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to manipulate or gain knowledge
  of sensitive information, bypass restrictions, cause a denial of service or compromise a vulnerable system." );
	script_tag( name: "affected", value: "Oracle Java JDK/JRE version 6 Update 21 on windows" );
	script_tag( name: "insight", value: "Multiple flaws are caused by errors in the 2D, CORBA, Deployment, JRE,
  Java Web Start, New Java Plug-in, Sound, Deployment Toolkit, JSSE, Kerberos, Networking, Swing, and JNDI components." );
	script_tag( name: "summary", value: "This host is installed with Oracle Java JDK/JRE and is prone to
  multiple vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to JDK/JRE version 6 Update 22." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
jdkVer = get_kb_item( "Sun/Java/JDK/Win/Ver" );
if(jdkVer){
	if(version_in_range( version: jdkVer, test_version: "1.6", test_version2: "1.6.0.21" )){
		report = report_fixed_ver( installed_version: jdkVer, vulnerable_range: "1.6 - 1.6.0.21" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
jreVer = get_kb_item( "Sun/Java/JRE/Win/Ver" );
if(jreVer){
	if(version_in_range( version: jreVer, test_version: "1.6", test_version2: "1.6.0.21" )){
		report = report_fixed_ver( installed_version: jreVer, vulnerable_range: "1.6 - 1.6.0.21" );
		security_message( port: 0, data: report );
	}
}

