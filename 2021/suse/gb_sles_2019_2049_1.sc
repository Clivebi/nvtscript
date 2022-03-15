if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.2049.1" );
	script_cve_id( "CVE-2018-16889", "CVE-2019-3821" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:21 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:2049-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:2049-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20192049-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ceph' package(s) announced via the SUSE-SU-2019:2049-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ceph fixes the following issues:

Security issues fixed:
CVE-2019-3821: civetweb: fix file descriptor leak (bsc#1125080)

CVE-2018-16889: rgw: sanitize customer encryption keys from log output
 in v4 auth (bsc#1121567)

Non-security issues fixed:
install grafana dashboards world readable (bsc#1136110)

upgrade results in cluster outage (bsc#1132396)

ceph status reports 'HEALTH_WARN 3 monitors have not enabled msgr2'
 (bsc#1124957)

 Dashboard: Opening tcmu-runner perf counters results in a 404
 (bsc#1135388)

RadosGW stopped expiring objects (bsc#1133139)

Ceph does not recover when rebuilding every OSD (bsc#1133461)" );
	script_tag( name: "affected", value: "'ceph' package(s) on SUSE Enterprise Storage 6, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
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
if(release == "SLES15.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "ceph-common", rpm: "ceph-common~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-common-debuginfo", rpm: "ceph-common-debuginfo~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-debugsource", rpm: "ceph-debugsource~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcephfs-devel", rpm: "libcephfs-devel~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcephfs2", rpm: "libcephfs2~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcephfs2-debuginfo", rpm: "libcephfs2-debuginfo~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librados-devel", rpm: "librados-devel~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librados-devel-debuginfo", rpm: "librados-devel-debuginfo~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librados2", rpm: "librados2~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librados2-debuginfo", rpm: "librados2-debuginfo~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libradospp-devel", rpm: "libradospp-devel~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librbd-devel", rpm: "librbd-devel~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librbd1", rpm: "librbd1~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librbd1-debuginfo", rpm: "librbd1-debuginfo~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librgw-devel", rpm: "librgw-devel~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librgw2", rpm: "librgw2~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librgw2-debuginfo", rpm: "librgw2-debuginfo~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-ceph-argparse", rpm: "python3-ceph-argparse~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-cephfs", rpm: "python3-cephfs~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-cephfs-debuginfo", rpm: "python3-cephfs-debuginfo~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-rados", rpm: "python3-rados~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-rados-debuginfo", rpm: "python3-rados-debuginfo~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-rbd", rpm: "python3-rbd~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-rbd-debuginfo", rpm: "python3-rbd-debuginfo~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-rgw", rpm: "python3-rgw~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-rgw-debuginfo", rpm: "python3-rgw-debuginfo~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rados-objclass-devel", rpm: "rados-objclass-devel~14.2.1.468+g994fd9e0cc~3.3.2", rls: "SLES15.0SP1" ) )){
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
