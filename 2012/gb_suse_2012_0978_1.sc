if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850307" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2012-12-13 17:01:42 +0530 (Thu, 13 Dec 2012)" );
	script_cve_id( "CVE-2012-2660", "CVE-2012-2694", "CVE-2012-2695" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "openSUSE-SU", value: "2012:0978-1" );
	script_name( "openSUSE: Security Advisory for rubygem-actionpack/activerecord-2_3 (openSUSE-SU-2012:0978-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rubygem-actionpack/activerecord-2_3'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSE11\\.4|openSUSE12\\.1)" );
	script_tag( name: "affected", value: "rubygem-actionpack/activerecord-2_3 on openSUSE 12.1, openSUSE 11.4" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "insight", value: "3 Security issues were fixed in rails 2.3 core components.

  2 NULL query issues where fixed in the actionpack gem. 1
  SQL injection was fixed in the activerecord gem." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "openSUSE11.4"){
	if(!isnull( res = isrpmvuln( pkg: "rubygem-actionpack-2_3", rpm: "rubygem-actionpack-2_3~2.3.14~0.16.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-actionpack-2_3-doc", rpm: "rubygem-actionpack-2_3-doc~2.3.14~0.16.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-actionpack-2_3-testsuite", rpm: "rubygem-actionpack-2_3-testsuite~2.3.14~0.16.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-activerecord-2_3", rpm: "rubygem-activerecord-2_3~2.3.14~0.16.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-activerecord-2_3-doc", rpm: "rubygem-activerecord-2_3-doc~2.3.14~0.16.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ubygem-activerecord-2_3-testsuite", rpm: "ubygem-activerecord-2_3-testsuite~2.3.14~0.16.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
if(release == "openSUSE12.1"){
	if(!isnull( res = isrpmvuln( pkg: "rubygem-actionpack-2_3", rpm: "rubygem-actionpack-2_3~2.3.14~3.8.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-actionpack-2_3-doc", rpm: "rubygem-actionpack-2_3-doc~2.3.14~3.8.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-actionpack-2_3-testsuite", rpm: "rubygem-actionpack-2_3-testsuite~2.3.14~3.8.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-activerecord-2_3", rpm: "rubygem-activerecord-2_3~2.3.14~3.8.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-activerecord-2_3-doc", rpm: "rubygem-activerecord-2_3-doc~2.3.14~3.8.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-activerecord-2_3-testsuite", rpm: "rubygem-activerecord-2_3-testsuite~2.3.14~3.8.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

