if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.102042" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-05-28 13:49:16 +0200 (Fri, 28 May 2010)" );
	script_cve_id( "CVE-2009-1106", "CVE-2009-1107", "CVE-2008-5352", "CVE-2008-5356", "CVE-2008-5353", "CVE-2008-5354", "CVE-2008-5357", "CVE-2008-5339", "CVE-2009-1104", "CVE-2008-5360", "CVE-2008-5344", "CVE-2008-5345", "CVE-2008-5346", "CVE-2009-1103", "CVE-2008-5347", "CVE-2008-5348", "CVE-2008-5349", "CVE-2008-5350", "CVE-2008-5351", "CVE-2009-1100", "CVE-2009-1101", "CVE-2009-1099", "CVE-2009-1098", "CVE-2009-1097", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1094", "CVE-2009-1093", "CVE-2008-5341", "CVE-2008-5359", "CVE-2008-5342", "CVE-2008-5340", "CVE-2008-2086", "CVE-2008-5343", "CVE-2009-1719" );
	script_name( "Java for Mac OS X 10.5 Update 4" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 LSS" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.5\\." );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT3632" );
	script_tag( name: "summary", value: "The remote host is missing Java for Mac OS X 10.5 Update 4." );
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
pkg_for_ver = make_list( "Mac OS X 10.5.7",
	 "Mac OS X Server 10.5.7" );
if(osx_rls_name( rls: ssh_osx_rls ) == osx_rls_name( rls: "Mac OS X 10.5.7" )){
	if(isosxpkgvuln( fixed: "com.apple.pkg.JavaForMacOSX10.5Update", diff: "4" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
if(osx_rls_name( rls: ssh_osx_rls ) == osx_rls_name( rls: "Mac OS X Server 10.5.7" )){
	if(isosxpkgvuln( fixed: "com.apple.pkg.JavaForMacOSX10.5Update", diff: "4" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

