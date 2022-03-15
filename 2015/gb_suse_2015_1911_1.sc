if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851127" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-11-05 06:19:57 +0100 (Thu, 05 Nov 2015)" );
	script_cve_id( "CVE-2015-7940" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for bouncycastle (openSUSE-SU-2015:1911-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bouncycastle'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "bouncycastle was updated to version 1.53 to fix one security issue.

  This security issue was fixed:

  - CVE-2015-7940: Invalid curve attack (bsc#951727)." );
	script_tag( name: "affected", value: "bouncycastle on openSUSE 13.2, openSUSE 13.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2015:1911-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSE13\\.2|openSUSE13\\.1)" );
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
if(release == "openSUSE13.2"){
	if(!isnull( res = isrpmvuln( pkg: "bouncycastle", rpm: "bouncycastle~1.53~13.3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bouncycastle-javadoc", rpm: "bouncycastle-javadoc~1.53~13.3.1", rls: "openSUSE13.2" ) )){
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
if(release == "openSUSE13.1"){
	if(!isnull( res = isrpmvuln( pkg: "bouncycastle", rpm: "bouncycastle~1.53~8.3.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ouncycastle-javadoc", rpm: "ouncycastle-javadoc~1.53~8.3.1", rls: "openSUSE13.1" ) )){
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

