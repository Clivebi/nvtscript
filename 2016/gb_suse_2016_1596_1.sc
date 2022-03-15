if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851342" );
	script_version( "2021-09-20T10:01:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 10:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-06-17 05:20:40 +0200 (Fri, 17 Jun 2016)" );
	script_cve_id( "CVE-2016-1583" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-06 22:29:00 +0000 (Thu, 06 Dec 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "SUSE: Security Advisory for kernel (SUSE-SU-2016:1596-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 GA kernel was updated to fix one security
  issue.

  The following security bug was fixed:

  - CVE-2016-1583: Prevent the usage of mmap when the lower file system does
  not allow it. This could have lead to local privilege escalation when
  ecryptfs-utils was installed and /sbin/mount.ecryptfs_private was setuid
  (bsc#983143)." );
	script_tag( name: "affected", value: "kernel on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Desktop 12" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "SUSE-SU", value: "2016:1596-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~3.12.55~52.45.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~3.12.55~52.45.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~3.12.55~52.45.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~3.12.55~52.45.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-extra", rpm: "kernel-default-extra~3.12.55~52.45.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-extra-debuginfo", rpm: "kernel-default-extra-debuginfo~3.12.55~52.45.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~3.12.55~52.45.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~3.12.55~52.45.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-debuginfo", rpm: "kernel-xen-debuginfo~3.12.55~52.45.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-debugsource", rpm: "kernel-xen-debugsource~3.12.55~52.45.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-devel", rpm: "kernel-xen-devel~3.12.55~52.45.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~3.12.55~52.45.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~3.12.55~52.45.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~3.12.55~52.45.1", rls: "SLED12.0SP0" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~3.12.55~52.45.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~3.12.55~52.45.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~3.12.55~52.45.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~3.12.55~52.45.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~3.12.55~52.45.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~3.12.55~52.45.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~3.12.55~52.45.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~3.12.55~52.45.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base", rpm: "kernel-xen-base~3.12.55~52.45.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base-debuginfo", rpm: "kernel-xen-base-debuginfo~3.12.55~52.45.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-debuginfo", rpm: "kernel-xen-debuginfo~3.12.55~52.45.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-debugsource", rpm: "kernel-xen-debugsource~3.12.55~52.45.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-devel", rpm: "kernel-xen-devel~3.12.55~52.45.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~3.12.55~52.45.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~3.12.55~52.45.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~3.12.55~52.45.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~3.12.55~52.45.1", rls: "SLES12.0SP0" ) )){
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

