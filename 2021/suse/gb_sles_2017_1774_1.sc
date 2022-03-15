if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.1774.1" );
	script_cve_id( "CVE-2016-10028", "CVE-2016-10029", "CVE-2016-9602", "CVE-2016-9603", "CVE-2017-5579", "CVE-2017-5973", "CVE-2017-5987", "CVE-2017-6505", "CVE-2017-7377", "CVE-2017-7471", "CVE-2017-7493", "CVE-2017-7718", "CVE-2017-7980", "CVE-2017-8086", "CVE-2017-8112", "CVE-2017-8309", "CVE-2017-8379", "CVE-2017-8380", "CVE-2017-9330", "CVE-2017-9373", "CVE-2017-9374", "CVE-2017-9375", "CVE-2017-9503" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-07 10:29:00 +0000 (Fri, 07 Sep 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:1774-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:1774-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20171774-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu' package(s) announced via the SUSE-SU-2017:1774-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for qemu fixes several issues.
These security issues were fixed:
- CVE-2017-9330: USB OHCI Emulation in qemu allowed local guest OS users
 to cause a denial of service (infinite loop) by leveraging an incorrect
 return value (bsc#1042159).
- CVE-2017-8379: Memory leak in the keyboard input event handlers support
 allowed local guest OS privileged users to cause a denial of service
 (host memory consumption) by rapidly generating large keyboard events
 (bsc#1037334).
- CVE-2017-8309: Memory leak in the audio/audio.c allowed remote attackers
 to cause a denial of service (memory consumption) by repeatedly starting
 and stopping audio capture (bsc#1037242).
- CVE-2017-7493: The VirtFS, host directory sharing via Plan 9 File
 System(9pfs) support, was vulnerable to an improper access control
 issue. It could occur while accessing virtfs metadata files in
 mapped-file security mode. A guest user could have used this flaw to
 escalate their privileges inside guest (bsc#1039495).
- CVE-2017-7377: The v9fs_create and v9fs_lcreate functions in
 hw/9pfs/9p.c allowed local guest OS privileged users to cause a denial
 of service (file descriptor or memory consumption) via vectors related
 to an already in-use fid (bsc#1032075).
- CVE-2017-8086: A memory leak in the v9fs_list_xattr function in
 hw/9pfs/9p-xattr.c allowed local guest OS privileged users to cause a
 denial of service (memory consumption) via vectors involving the
 orig_value variable (bsc#1035950).
- CVE-2017-5973: A infinite loop while doing control transfer in
 xhci_kick_epctx allowed privileged user inside the guest to crash the
 host process resulting in DoS (bsc#1025109)
- CVE-2017-5987: The sdhci_sdma_transfer_multi_blocks function in
 hw/sd/sdhci.c allowed local OS guest privileged users to cause a denial
 of service (infinite loop and QEMU process crash) via vectors involving
 the transfer mode register during multi block transfer (bsc#1025311).
- CVE-2017-6505: The ohci_service_ed_list function in hw/usb/hcd-ohci.c
 allowed local guest OS users to cause a denial of service (infinite
 loop) via vectors involving the number of link endpoint list descriptors
 (bsc#1028184)
- CVE-2016-9603: A privileged user within the guest VM could have caused a
 heap overflow in the device model process, potentially escalating their
 privileges to that of the device model process (bsc#1028656)
- CVE-2017-7718: hw/display/cirrus_vga_rop.h allowed local guest OS
 privileged users to cause a denial of service (out-of-bounds read and
 QEMU process crash) via vectors related to copying VGA data via the
 cirrus_bitblt_rop_fwd_transp_ and cirrus_bitblt_rop_fwd_ functions
 (bsc#1034908)
- CVE-2017-7980: An out-of-bounds r/w access issues in the Cirrus CLGD
 54xx VGA Emulator support allowed privileged user inside guest to use
 this flaw to crash the Qemu process resulting in DoS or potentially
 execute arbitrary code on a ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'qemu' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2." );
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "qemu", rpm: "qemu~2.6.2~41.16.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-arm", rpm: "qemu-arm~2.6.2~41.16.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-arm-debuginfo", rpm: "qemu-arm-debuginfo~2.6.2~41.16.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-curl", rpm: "qemu-block-curl~2.6.2~41.16.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-curl-debuginfo", rpm: "qemu-block-curl-debuginfo~2.6.2~41.16.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-rbd", rpm: "qemu-block-rbd~2.6.2~41.16.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-rbd-debuginfo", rpm: "qemu-block-rbd-debuginfo~2.6.2~41.16.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-ssh", rpm: "qemu-block-ssh~2.6.2~41.16.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-ssh-debuginfo", rpm: "qemu-block-ssh-debuginfo~2.6.2~41.16.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-debugsource", rpm: "qemu-debugsource~2.6.2~41.16.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-guest-agent", rpm: "qemu-guest-agent~2.6.2~41.16.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-guest-agent-debuginfo", rpm: "qemu-guest-agent-debuginfo~2.6.2~41.16.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ipxe", rpm: "qemu-ipxe~1.0.0~41.16.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-kvm", rpm: "qemu-kvm~2.6.2~41.16.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-lang", rpm: "qemu-lang~2.6.2~41.16.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ppc", rpm: "qemu-ppc~2.6.2~41.16.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ppc-debuginfo", rpm: "qemu-ppc-debuginfo~2.6.2~41.16.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-seabios", rpm: "qemu-seabios~1.9.1~41.16.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-sgabios", rpm: "qemu-sgabios~8~41.16.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-tools", rpm: "qemu-tools~2.6.2~41.16.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-tools-debuginfo", rpm: "qemu-tools-debuginfo~2.6.2~41.16.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-vgabios", rpm: "qemu-vgabios~1.9.1~41.16.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-x86", rpm: "qemu-x86~2.6.2~41.16.1", rls: "SLES12.0SP2" ) )){
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

