if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.1324.1" );
	script_cve_id( "CVE-2014-9728", "CVE-2014-9729", "CVE-2014-9730", "CVE-2014-9731", "CVE-2015-1805", "CVE-2015-3212", "CVE-2015-4036", "CVE-2015-4167", "CVE-2015-4692", "CVE-2015-5364", "CVE-2015-5366" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:1324-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:1324-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20151324-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'SUSE Linux Enterprise 12 kernel' package(s) announced via the SUSE-SU-2015:1324-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 kernel was updated to 3.12.44 to receive various security and bugfixes.
These features were added:
- mpt2sas: Added Reply Descriptor Post Queue (RDPQ) Array support
 (bsc#854824).
- mpt3sas: Bump mpt3sas driver version to 04.100.00.00 (bsc#854817).
Following security bugs were fixed:
- CVE-2015-1805: iov overrun for failed atomic copy could have lead to DoS
 or privilege escalation (bsc#933429).
- CVE-2015-3212: A race condition in the way the Linux kernel handled
 lists of associations in SCTP sockets could have lead to list corruption
 and kernel panics (bsc#936502).
- CVE-2015-4036: DoS via memory corruption in vhost/scsi driver
 (bsc#931988).
- CVE-2015-4167: Linux kernel built with the UDF file
 system(CONFIG_UDF_FS) support was vulnerable to a crash. It occurred
 while fetching inode information from a corrupted/malicious udf file
 system image (bsc#933907).
- CVE-2015-4692: DoS via NULL pointer dereference in kvm_apic_has_events
 function (bsc#935542).
- CVE-2015-5364: Remote DoS via flood of UDP packets with invalid
 checksums (bsc#936831).
- CVE-2015-5366: Remote DoS of EPOLLET epoll applications via flood of UDP
 packets with invalid checksums (bsc#936831).
Security issues already fixed in the previous update but not referenced by CVE:
- CVE-2014-9728: Kernel built with the UDF file system(CONFIG_UDF_FS)
 support were vulnerable to a crash (bsc#933904).
- CVE-2014-9729: Kernel built with the UDF file system(CONFIG_UDF_FS)
 support were vulnerable to a crash (bsc#933904).
- CVE-2014-9730: Kernel built with the UDF file system(CONFIG_UDF_FS)
 support were vulnerable to a crash (bsc#933904).
- CVE-2014-9731: Kernel built with the UDF file system(CONFIG_UDF_FS)
 support were vulnerable to information leakage (bsc#933896).
The following non-security bugs were fixed:
- ALSA: hda - add codec ID for Skylake display audio codec (bsc#936556).
- ALSA: hda/hdmi - apply Haswell fix-ups to Skylake display codec
 (bsc#936556).
- ALSA: hda_controller: Separate stream_tag for input and output streams
 (bsc#936556).
- ALSA: hda_intel: add AZX_DCAPS_I915_POWERWELL for SKL and BSW
 (bsc#936556).
- ALSA: hda_intel: apply the Separate stream_tag for Skylake (bsc#936556).
- ALSA: hda_intel: apply the Separate stream_tag for Sunrise Point
 (bsc#936556).
- Btrfs: Handle unaligned length in extent_same (bsc#937609).
- Btrfs: add missing inode item update in fallocate() (bsc#938023).
- Btrfs: check pending chunks when shrinking fs to avoid corruption
 (bsc#936445).
- Btrfs: do not update mtime/ctime on deduped inodes (bsc#937616).
- Btrfs: fix block group ->space_info null pointer dereference
 (bsc#935088).
- Btrfs: fix clone / extent-same deadlocks (bsc#937612).
- Btrfs: fix deadlock with extent-same and readpage (bsc#937612).
- Btrfs: fix fsync data loss after append write (bsc#936446).
- Btrfs: fix hang during inode eviction due to concurrent readahead
 ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'SUSE Linux Enterprise 12 kernel' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Live Patching 12, SUSE Linux Enterprise Module for Public Cloud 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Software Development Kit 12, SUSE Linux Enterprise Workstation Extension 12." );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2", rpm: "kernel-ec2~3.12.44~52.10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-debuginfo", rpm: "kernel-ec2-debuginfo~3.12.44~52.10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-debugsource", rpm: "kernel-ec2-debugsource~3.12.44~52.10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-devel", rpm: "kernel-ec2-devel~3.12.44~52.10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-extra", rpm: "kernel-ec2-extra~3.12.44~52.10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-extra-debuginfo", rpm: "kernel-ec2-extra-debuginfo~3.12.44~52.10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~3.12.44~52.10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~3.12.44~52.10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~3.12.44~52.10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~3.12.44~52.10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~3.12.44~52.10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~3.12.44~52.10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~3.12.44~52.10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~3.12.44~52.10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~3.12.44~52.10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~3.12.44~52.10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~3.12.44~52.10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~3.12.44~52.10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base", rpm: "kernel-xen-base~3.12.44~52.10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base-debuginfo", rpm: "kernel-xen-base-debuginfo~3.12.44~52.10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-debuginfo", rpm: "kernel-xen-debuginfo~3.12.44~52.10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-debugsource", rpm: "kernel-xen-debugsource~3.12.44~52.10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-devel", rpm: "kernel-xen-devel~3.12.44~52.10.1", rls: "SLES12.0" ) )){
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

