if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851065" );
	script_version( "2020-01-31T07:58:03+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-10-16 19:19:06 +0200 (Fri, 16 Oct 2015)" );
	script_cve_id( "CVE-2014-2977", "CVE-2014-2978" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "SUSE: Security Advisory for DirectFB (SUSE-SU-2015:0839-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'DirectFB'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "DirectFB was updated to fix two security issues.

  The following vulnerabilities were fixed:

  * CVE-2014-2977: Multiple integer signedness errors could allow remote
  attackers to cause a denial of service (crash) and possibly execute
  arbitrary code via the Voodoo interface, which triggers a stack-based
  buffer overflow.

  * CVE-2014-2978: Remote attackers could cause a denial of service (crash)
  and possibly execute arbitrary code via the Voodoo interface, which
  triggers an out-of-bounds write." );
	script_tag( name: "affected", value: "DirectFB on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Desktop 12" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "SUSE-SU", value: "2015:0839-1" );
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
	if(!isnull( res = isrpmvuln( pkg: "DirectFB", rpm: "DirectFB~1.7.1~4.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "DirectFB-debuginfo", rpm: "DirectFB-debuginfo~1.7.1~4.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "DirectFB-debugsource", rpm: "DirectFB-debugsource~1.7.1~4.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lib++dfb-1_7-1", rpm: "lib++dfb-1_7-1~1.7.1~4.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lib++dfb-1_7-1-debuginfo", rpm: "lib++dfb-1_7-1-debuginfo~1.7.1~4.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdirectfb-1_7-1", rpm: "libdirectfb-1_7-1~1.7.1~4.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdirectfb-1_7-1-32bit", rpm: "libdirectfb-1_7-1-32bit~1.7.1~4.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdirectfb-1_7-1-debuginfo", rpm: "libdirectfb-1_7-1-debuginfo~1.7.1~4.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdirectfb-1_7-1-debuginfo-32bit", rpm: "libdirectfb-1_7-1-debuginfo-32bit~1.7.1~4.1", rls: "SLED12.0SP0" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "DirectFB", rpm: "DirectFB~1.7.1~4.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "DirectFB-debuginfo", rpm: "DirectFB-debuginfo~1.7.1~4.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "DirectFB-debugsource", rpm: "DirectFB-debugsource~1.7.1~4.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lib++dfb-1_7-1", rpm: "lib++dfb-1_7-1~1.7.1~4.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lib++dfb-1_7-1-debuginfo", rpm: "lib++dfb-1_7-1-debuginfo~1.7.1~4.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdirectfb-1_7-1", rpm: "libdirectfb-1_7-1~1.7.1~4.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdirectfb-1_7-1-debuginfo", rpm: "libdirectfb-1_7-1-debuginfo~1.7.1~4.1", rls: "SLES12.0SP0" ) )){
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

