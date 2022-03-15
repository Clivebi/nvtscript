if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850328" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2012-12-13 17:02:04 +0530 (Thu, 13 Dec 2012)" );
	script_cve_id( "CVE-2012-4244" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_xref( name: "openSUSE-SU", value: "2012:1192-1" );
	script_name( "openSUSE: Security Advisory for bind (openSUSE-SU-2012:1192-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bind'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSE11\\.4|openSUSE12\\.1)" );
	script_tag( name: "affected", value: "bind on openSUSE 12.1, openSUSE 11.4" );
	script_tag( name: "insight", value: "A remote denial of service attack was fixed in the BIND DNS
  nameserver, which could be caused by attackers providing a
  specifically prepared zone file for recursive transfer.
  (CVE-2012-4244)" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
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
	if(!isnull( res = isrpmvuln( pkg: "bind", rpm: "bind~9.7.6P3~0.37.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-chrootenv", rpm: "bind-chrootenv~9.7.6P3~0.37.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-debuginfo", rpm: "bind-debuginfo~9.7.6P3~0.37.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-debugsource", rpm: "bind-debugsource~9.7.6P3~0.37.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-devel", rpm: "bind-devel~9.7.6P3~0.37.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs", rpm: "bind-libs~9.7.6P3~0.37.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs-debuginfo", rpm: "bind-libs-debuginfo~9.7.6P3~0.37.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-lwresd", rpm: "bind-lwresd~9.7.6P3~0.37.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-lwresd-debuginfo", rpm: "bind-lwresd-debuginfo~9.7.6P3~0.37.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-utils", rpm: "bind-utils~9.7.6P3~0.37.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-utils-debuginfo", rpm: "bind-utils-debuginfo~9.7.6P3~0.37.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs-32bit", rpm: "bind-libs-32bit~9.7.6P3~0.37.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs-debuginfo-32bit", rpm: "bind-libs-debuginfo-32bit~9.7.6P3~0.37.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-doc", rpm: "bind-doc~9.7.6P3~0.37.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs-debuginfo-x86", rpm: "bind-libs-debuginfo-x86~9.7.6P3~0.37.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ind-libs-x86", rpm: "ind-libs-x86~9.7.6P3~0.37.1", rls: "openSUSE11.4" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "bind", rpm: "bind~9.8.3P3~4.20.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-chrootenv", rpm: "bind-chrootenv~9.8.3P3~4.20.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-debuginfo", rpm: "bind-debuginfo~9.8.3P3~4.20.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-debugsource", rpm: "bind-debugsource~9.8.3P3~4.20.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-devel", rpm: "bind-devel~9.8.3P3~4.20.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs", rpm: "bind-libs~9.8.3P3~4.20.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs-debuginfo", rpm: "bind-libs-debuginfo~9.8.3P3~4.20.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-lwresd", rpm: "bind-lwresd~9.8.3P3~4.20.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-lwresd-debuginfo", rpm: "bind-lwresd-debuginfo~9.8.3P3~4.20.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-utils", rpm: "bind-utils~9.8.3P3~4.20.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-utils-debuginfo", rpm: "bind-utils-debuginfo~9.8.3P3~4.20.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs-32bit", rpm: "bind-libs-32bit~9.8.3P3~4.20.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs-debuginfo-32bit", rpm: "bind-libs-debuginfo-32bit~9.8.3P3~4.20.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-doc", rpm: "bind-doc~9.8.3P3~4.20.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs-debuginfo-x86", rpm: "bind-libs-debuginfo-x86~9.8.3P3~4.20.1", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs-x86", rpm: "bind-libs-x86~9.8.3P3~4.20.1", rls: "openSUSE12.1" ) )){
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

