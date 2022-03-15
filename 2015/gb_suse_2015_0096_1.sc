if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850923" );
	script_version( "2020-01-31T07:58:03+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-10-16 14:29:27 +0200 (Fri, 16 Oct 2015)" );
	script_cve_id( "CVE-2014-8500" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "SUSE: Security Advisory for bind (SUSE-SU-2015:0096-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bind'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update of bind to 9.9.6P1 fixes bugs and also the following security
  issue:

  A flaw in delegation handling could be exploited to put named into an
  infinite loop.  This has been addressed by placing limits on the number of
  levels of recursion named will allow (default 7), and the number of
  iterative queries that it will send (default 50) before terminating a
  recursive query (CVE-2014-8500, bnc#908994).

  The recursion depth limit is configured via the 'max-recursion-depth'
  option, and the query limit via the 'max-recursion-queries' option.

  Also the rpz2 patch was removed as it is no longer maintained." );
	script_tag( name: "affected", value: "bind on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Desktop 12" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "SUSE-SU", value: "2015:0096-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(SLED12\\.0SP0|SLES12\\.0SP0)" );
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
if(release == "SLED12.0SP0"){
	if(!isnull( res = isrpmvuln( pkg: "bind-debuginfo", rpm: "bind-debuginfo~9.9.5P1~8.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-debugsource", rpm: "bind-debugsource~9.9.5P1~8.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs-32bit", rpm: "bind-libs-32bit~9.9.5P1~8.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs", rpm: "bind-libs~9.9.5P1~8.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs-debuginfo-32bit", rpm: "bind-libs-debuginfo-32bit~9.9.5P1~8.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs-debuginfo", rpm: "bind-libs-debuginfo~9.9.5P1~8.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-utils", rpm: "bind-utils~9.9.5P1~8.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ind-utils-debuginfo", rpm: "ind-utils-debuginfo~9.9.5P1~8.1", rls: "SLED12.0SP0" ) )){
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
if(release == "SLES12.0SP0"){
	if(!isnull( res = isrpmvuln( pkg: "bind", rpm: "bind~9.9.5P1~8.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-chrootenv", rpm: "bind-chrootenv~9.9.5P1~8.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-debuginfo", rpm: "bind-debuginfo~9.9.5P1~8.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-debugsource", rpm: "bind-debugsource~9.9.5P1~8.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs", rpm: "bind-libs~9.9.5P1~8.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs-debuginfo", rpm: "bind-libs-debuginfo~9.9.5P1~8.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-utils", rpm: "bind-utils~9.9.5P1~8.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-utils-debuginfo", rpm: "bind-utils-debuginfo~9.9.5P1~8.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs-32bit", rpm: "bind-libs-32bit~9.9.5P1~8.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs-debuginfo-32bit", rpm: "bind-libs-debuginfo-32bit~9.9.5P1~8.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-doc", rpm: "bind-doc~9.9.5P1~8.1", rls: "SLES12.0SP0" ) )){
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

