if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.102044" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-05-28 13:49:16 +0200 (Fri, 28 May 2010)" );
	script_cve_id( "CVE-2009-3869", "CVE-2009-3871", "CVE-2009-3875", "CVE-2009-3874", "CVE-2009-3728", "CVE-2009-3872", "CVE-2009-3868", "CVE-2009-3867", "CVE-2009-3884", "CVE-2009-3873", "CVE-2009-3877", "CVE-2009-3865", "CVE-2009-3866", "CVE-2009-2843" );
	script_name( "Java for Mac OS X 10.5 Update 6" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 LSS" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.5\\." );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT3970" );
	script_tag( name: "summary", value: "The remote host is missing Java for Mac OS X 10.5 Update 6." );
	script_tag( name: "affected", value: "One or more of the following components are affected:

  Java" );
	script_tag( name: "solution", value: "Update your Java for Mac OS X. Please see the references for more information." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-macosx.inc.sc");
ssh_osx_name = get_kb_item( "ssh/login/osx_name" );
if(!ssh_osx_name){
	exit( 0 );
}
ssh_osx_ver = get_kb_item( "ssh/login/osx_version" );
if(!ssh_osx_ver || !IsMatchRegexp( ssh_osx_ver, "^10\\.5\\." )){
	exit( 0 );
}
ssh_osx_rls = ssh_osx_name + " " + ssh_osx_ver;
pkg_for_ver = make_list( "Mac OS X 10.5.8",
	 "Mac OS X Server 10.5.8" );
if(osx_rls_name( rls: ssh_osx_rls ) == osx_rls_name( rls: "Mac OS X 10.5.8" )){
	if(isosxpkgvuln( fixed: "com.apple.pkg.JavaForMacOSX10.5Update", diff: "6" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
if(osx_rls_name( rls: ssh_osx_rls ) == osx_rls_name( rls: "Mac OS X Server 10.5.8" )){
	if(isosxpkgvuln( fixed: "com.apple.pkg.JavaForMacOSX10.5Update", diff: "6" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

