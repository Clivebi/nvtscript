if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.2764.1" );
	script_cve_id( "CVE-2016-5011" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-11 15:22:00 +0000 (Fri, 11 Sep 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:2764-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:2764-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20162764-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'util-linux' package(s) announced via the SUSE-SU-2016:2764-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for util-linux fixes a number of bugs and one minor security issue.
The following minor vulnerability was fixed:
- CVE-2016-5011: Infinite loop DoS in libblkid while parsing DOS partition
 (bsc#988361)
The following bugs were fixed:
- bsc#987176: When mounting a subfolder of a CIFS share, mount -a would
 show the mount as busy
- bsc#947494: mount -a would fail to recognize btrfs already mounted,
 address loop re-use in libmount
- bsc#966891: Conflict in meaning of losetup -L. This switch in SLE12 SP1
 and SP2 continues to carry the meaning of --logical-blocksize instead of
 upstream --nooverlap
- bsc#994399: Package would trigger conflicts with sysvinit-tools
- bsc#983164: mount uid= and gid= would reject valid non UID/GID values
- bsc#978993: cfdisk would mangle some text output
- bsc#982331: libmount: ignore redundant slashes" );
	script_tag( name: "affected", value: "'util-linux' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP1, SUSE Linux Enterprise Workstation Extension 12-SP1." );
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "libblkid1", rpm: "libblkid1~2.25~37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libblkid1-32bit", rpm: "libblkid1-32bit~2.25~37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libblkid1-debuginfo", rpm: "libblkid1-debuginfo~2.25~37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libblkid1-debuginfo-32bit", rpm: "libblkid1-debuginfo-32bit~2.25~37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmount1", rpm: "libmount1~2.25~37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmount1-32bit", rpm: "libmount1-32bit~2.25~37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmount1-debuginfo", rpm: "libmount1-debuginfo~2.25~37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmount1-debuginfo-32bit", rpm: "libmount1-debuginfo-32bit~2.25~37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmartcols1", rpm: "libsmartcols1~2.25~37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmartcols1-debuginfo", rpm: "libsmartcols1-debuginfo~2.25~37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libuuid1", rpm: "libuuid1~2.25~37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libuuid1-32bit", rpm: "libuuid1-32bit~2.25~37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libuuid1-debuginfo", rpm: "libuuid1-debuginfo~2.25~37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libuuid1-debuginfo-32bit", rpm: "libuuid1-debuginfo-32bit~2.25~37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-libmount", rpm: "python-libmount~2.25~37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-libmount-debuginfo", rpm: "python-libmount-debuginfo~2.25~37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-libmount-debugsource", rpm: "python-libmount-debugsource~2.25~37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "util-linux", rpm: "util-linux~2.25~37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "util-linux-debuginfo", rpm: "util-linux-debuginfo~2.25~37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "util-linux-debugsource", rpm: "util-linux-debugsource~2.25~37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "util-linux-lang", rpm: "util-linux-lang~2.25~37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "util-linux-systemd", rpm: "util-linux-systemd~2.25~37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "util-linux-systemd-debuginfo", rpm: "util-linux-systemd-debuginfo~2.25~37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "util-linux-systemd-debugsource", rpm: "util-linux-systemd-debugsource~2.25~37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "uuidd", rpm: "uuidd~2.25~37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "uuidd-debuginfo", rpm: "uuidd-debuginfo~2.25~37.1", rls: "SLES12.0SP1" ) )){
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

