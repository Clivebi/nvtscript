if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.1748.1" );
	script_cve_id( "CVE-2020-10753" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-28 19:56:00 +0000 (Fri, 28 May 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:1748-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3|SLES12\\.0SP4|SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:1748-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20201748-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ceph' package(s) announced via the SUSE-SU-2020:1748-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This is a version update for ceph to version 12.2.13:

Security issue fixed:

CVE-2020-10753: Fixed an HTTP header injection via CORS ExposeHeader tag
 (bsc#1171921).

Notable changes in this update for ceph:
 * mgr: telemetry: backported and now available on SES5.5. Please
 consider enabling via 'ceph telemetry on' (bsc#1171670)
 * OSD heartbeat ping time: new health warning, options and admin
 commands (bsc#1171960)
 * 'osd_calc_pg_upmaps_max_stddev' ceph.conf parameter has been removed,
 use 'upmap_max_deviation' instead (bsc#1171961)
 * Default maximum concurrent bluestore rocksdb compaction threads raised
 from 1 to 2 for improved ability to keep up with rgw bucket index
 workloads (bsc#1171963)

Bug fixes in this ceph update:
 * mon: Error message displayed when mon_osd_max_split_count would be
 exceeded is not as user-friendly as it could be (bsc#1126230)
 * ceph_volume_client: remove ceph mds calls in favor of ceph fs calls
 (bsc#1136082)
 * rgw: crypt: permit RGW-AUTO/default with SSE-S3 headers (bsc#1157607)
 * mon/AuthMonitor: don't validate fs caps on authorize (bsc#1161096)

Additional bug fixes:
 * ceph-volume: strip _dmcrypt suffix in simple scan json output
 (bsc#1162553)" );
	script_tag( name: "affected", value: "'ceph' package(s) on HPE Helion Openstack 8, SUSE Enterprise Storage 5, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud Crowbar 8." );
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "ceph-common", rpm: "ceph-common~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-common-debuginfo", rpm: "ceph-common-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-debugsource", rpm: "ceph-debugsource~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcephfs2", rpm: "libcephfs2~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcephfs2-debuginfo", rpm: "libcephfs2-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librados2", rpm: "librados2~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librados2-debuginfo", rpm: "librados2-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libradosstriper1", rpm: "libradosstriper1~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libradosstriper1-debuginfo", rpm: "libradosstriper1-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librbd1", rpm: "librbd1~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librbd1-debuginfo", rpm: "librbd1-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librgw2", rpm: "librgw2~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librgw2-debuginfo", rpm: "librgw2-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-cephfs", rpm: "python-cephfs~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-cephfs-debuginfo", rpm: "python-cephfs-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rados", rpm: "python-rados~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rados-debuginfo", rpm: "python-rados-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rbd", rpm: "python-rbd~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rbd-debuginfo", rpm: "python-rbd-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rgw", rpm: "python-rgw~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rgw-debuginfo", rpm: "python-rgw-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP3" ) )){
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "ceph-common", rpm: "ceph-common~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-common-debuginfo", rpm: "ceph-common-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-debugsource", rpm: "ceph-debugsource~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcephfs2", rpm: "libcephfs2~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcephfs2-debuginfo", rpm: "libcephfs2-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librados2", rpm: "librados2~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librados2-debuginfo", rpm: "librados2-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libradosstriper1", rpm: "libradosstriper1~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libradosstriper1-debuginfo", rpm: "libradosstriper1-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librbd1", rpm: "librbd1~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librbd1-debuginfo", rpm: "librbd1-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librgw2", rpm: "librgw2~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librgw2-debuginfo", rpm: "librgw2-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-cephfs", rpm: "python-cephfs~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-cephfs-debuginfo", rpm: "python-cephfs-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rados", rpm: "python-rados~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rados-debuginfo", rpm: "python-rados-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rbd", rpm: "python-rbd~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rbd-debuginfo", rpm: "python-rbd-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rgw", rpm: "python-rgw~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rgw-debuginfo", rpm: "python-rgw-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP4" ) )){
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
if(release == "SLES12.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "ceph-common", rpm: "ceph-common~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-common-debuginfo", rpm: "ceph-common-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-debugsource", rpm: "ceph-debugsource~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcephfs2", rpm: "libcephfs2~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcephfs2-debuginfo", rpm: "libcephfs2-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librados2", rpm: "librados2~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librados2-debuginfo", rpm: "librados2-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libradosstriper1", rpm: "libradosstriper1~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libradosstriper1-debuginfo", rpm: "libradosstriper1-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librbd1", rpm: "librbd1~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librbd1-debuginfo", rpm: "librbd1-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librgw2", rpm: "librgw2~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librgw2-debuginfo", rpm: "librgw2-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-cephfs", rpm: "python-cephfs~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-cephfs-debuginfo", rpm: "python-cephfs-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rados", rpm: "python-rados~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rados-debuginfo", rpm: "python-rados-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rbd", rpm: "python-rbd~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rbd-debuginfo", rpm: "python-rbd-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rgw", rpm: "python-rgw~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rgw-debuginfo", rpm: "python-rgw-debuginfo~12.2.13+git.1592168685.85110a3e9d~2.50.1", rls: "SLES12.0SP5" ) )){
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

