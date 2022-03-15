if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852340" );
	script_version( "2021-09-07T10:01:34+0000" );
	script_cve_id( "CVE-2018-14662", "CVE-2018-16846", "CVE-2018-16889" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-07 10:01:34 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-03-09 04:09:21 +0100 (Sat, 09 Mar 2019)" );
	script_name( "openSUSE: Security Advisory for ceph (openSUSE-SU-2019:0306-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2019:0306-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-03/msg00016.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ceph'
  package(s) announced via the openSUSE-SU-2019:0306-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ceph fixes the following issues:

  Security issues fixed:

  - CVE-2018-14662: mon: limit caps allowed to access the config store
  (bsc#1111177)

  - CVE-2018-16846: rgw: enforce bounds on max-keys/max-uploads/max-parts
  (bsc#1114710)

  - CVE-2018-16889: rgw: sanitize customer encryption keys from log output
  in v4 auth (bsc#1121567)

  Non-security issue fixed:

  - os/bluestore: avoid frequent allocator dump on bluefs rebalance failure
  (bsc#1113246)

  This update was imported from the SUSE:SLE-12-SP3:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-306=1" );
	script_tag( name: "affected", value: "ceph on openSUSE Leap 42.3." );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "ceph", rpm: "ceph~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-base", rpm: "ceph-base~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-base-debuginfo", rpm: "ceph-base-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-common", rpm: "ceph-common~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-common-debuginfo", rpm: "ceph-common-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-debugsource", rpm: "ceph-debugsource~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-fuse", rpm: "ceph-fuse~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-fuse-debuginfo", rpm: "ceph-fuse-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-mds", rpm: "ceph-mds~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-mds-debuginfo", rpm: "ceph-mds-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-mgr", rpm: "ceph-mgr~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-mgr-debuginfo", rpm: "ceph-mgr-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-mon", rpm: "ceph-mon~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-mon-debuginfo", rpm: "ceph-mon-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-osd", rpm: "ceph-osd~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-osd-debuginfo", rpm: "ceph-osd-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-radosgw", rpm: "ceph-radosgw~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-radosgw-debuginfo", rpm: "ceph-radosgw-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-resource-agents", rpm: "ceph-resource-agents~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-test", rpm: "ceph-test~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-test-debuginfo", rpm: "ceph-test-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ceph-test-debugsource", rpm: "ceph-test-debugsource~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcephfs-devel", rpm: "libcephfs-devel~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcephfs2", rpm: "libcephfs2~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcephfs2-debuginfo", rpm: "libcephfs2-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librados-devel", rpm: "librados-devel~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librados-devel-debuginfo", rpm: "librados-devel-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librados2", rpm: "librados2~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librados2-debuginfo", rpm: "librados2-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libradosstriper-devel", rpm: "libradosstriper-devel~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libradosstriper1", rpm: "libradosstriper1~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libradosstriper1-debuginfo", rpm: "libradosstriper1-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librbd-devel", rpm: "librbd-devel~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librbd1", rpm: "librbd1~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librbd1-debuginfo", rpm: "librbd1-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librgw-devel", rpm: "librgw-devel~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librgw2", rpm: "librgw2~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "librgw2-debuginfo", rpm: "librgw2-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-ceph-compat", rpm: "python-ceph-compat~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-cephfs", rpm: "python-cephfs~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-cephfs-debuginfo", rpm: "python-cephfs-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rados", rpm: "python-rados~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rados-debuginfo", rpm: "python-rados-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rbd", rpm: "python-rbd~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rbd-debuginfo", rpm: "python-rbd-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rgw", rpm: "python-rgw~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rgw-debuginfo", rpm: "python-rgw-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-ceph-argparse", rpm: "python3-ceph-argparse~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-cephfs", rpm: "python3-cephfs~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-cephfs-debuginfo", rpm: "python3-cephfs-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-rados", rpm: "python3-rados~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-rados-debuginfo", rpm: "python3-rados-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-rbd", rpm: "python3-rbd~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-rbd-debuginfo", rpm: "python3-rbd-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-rgw", rpm: "python3-rgw~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-rgw-debuginfo", rpm: "python3-rgw-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rados-objclass-devel", rpm: "rados-objclass-devel~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rbd-fuse", rpm: "rbd-fuse~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rbd-fuse-debuginfo", rpm: "rbd-fuse-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rbd-mirror", rpm: "rbd-mirror~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rbd-mirror-debuginfo", rpm: "rbd-mirror-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rbd-nbd", rpm: "rbd-nbd~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "d-nbd-debuginfo", rpm: "d-nbd-debuginfo~12.2.10+git.1549630712.bb089269ea~21.1", rls: "openSUSELeap42.3" ) )){
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

