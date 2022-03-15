if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.1245.1" );
	script_cve_id( "CVE-2020-11947", "CVE-2020-12829", "CVE-2020-13361", "CVE-2020-13362", "CVE-2020-13659", "CVE-2020-13765", "CVE-2020-14364", "CVE-2020-15469", "CVE-2020-15863", "CVE-2020-16092", "CVE-2020-25084", "CVE-2020-25624", "CVE-2020-25625", "CVE-2020-25723", "CVE-2020-27617", "CVE-2020-27821", "CVE-2020-28916", "CVE-2020-29129", "CVE-2020-29130", "CVE-2020-29443", "CVE-2021-20181", "CVE-2021-20203", "CVE-2021-20221", "CVE-2021-20257", "CVE-2021-3416" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 11:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:1245-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:1245-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20211245-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu' package(s) announced via the SUSE-SU-2021:1245-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for qemu fixes the following issues:


Fix OOB access in sm501 device emulation (CVE-2020-12829, bsc#1172385)

Fix OOB access possibility in MegaRAID SAS 8708EM2 emulation
 (CVE-2020-13362 bsc#1172383)

Fix use-after-free in usb xhci packet handling (CVE-2020-25723,
 bsc#1178934)

Fix use-after-free in usb ehci packet handling (CVE-2020-25084,
 bsc#1176673)

Fix OOB access in usb hcd-ohci emulation (CVE-2020-25624, bsc#1176682)

Fix infinite loop (DoS) in usb hcd-ohci emulation (CVE-2020-25625,
 bsc#1176684)

Fix guest triggerable assert in shared network handling code
 (CVE-2020-27617, bsc#1178174)

Fix infinite loop (DoS) in e1000e device emulation (CVE-2020-28916,
 bsc#1179468)

Fix OOB access in atapi emulation (CVE-2020-29443, bsc#1181108)

Fix heap overflow in MSIx emulation (CVE-2020-27821, bsc#1179686)

Fix null pointer deref. (DoS) in mmio ops (CVE-2020-15469, bsc#1173612)

Fix infinite loop (DoS) in e1000 device emulation (CVE-2021-20257,
 bsc#1182577)

Fix OOB access (stack overflow) in rtl8139 NIC emulation (CVE-2021-3416,
 bsc#1182968)

Fix OOB access (stack overflow) in other NIC emulations (CVE-2021-3416)

Fix OOB access in SLIRP ARP/NCSI packet processing (CVE-2020-29129,
 bsc#1179466, CVE-2020-29130, bsc#1179467)

Fix null pointer dereference possibility (DoS) in MegaRAID SAS 8708EM2
 emulation (CVE-2020-13659 bsc#1172386)

Fix issue where s390 guest fails to find zipl boot menu index
 (bsc#1183979)

Fix OOB access in iscsi (CVE-2020-11947 bsc#1180523)

Fix OOB access in vmxnet3 emulation (CVE-2021-20203 bsc#1181639)

Fix package scripts to not use hard coded paths for temporary working
 directories and log files (bsc#1182425)

Fix potential privilege escalation in virtfs (CVE-2021-20181 bsc#1182137)

Apply fixes to qemu scsi passthrough with respect to timeout and error
 conditions, including using more correct status codes. (bsc#1178049)

Fix OOB access in ARM interrupt handling (CVE-2021-20221 bsc#1181933)

Tweaks to spec file for better formatting, and remove not needed
 BuildRequires for e2fsprogs-devel and libpcap-devel

Fix OOB access possibility in ES1370 audio device emulation
 (CVE-2020-13361 bsc#1172384)

Fix OOB access in ROM loading (CVE-2020-13765 bsc#1172478)

Fix OOB access while processing USB packets (CVE-2020-14364 bsc#1175441)

Fix DoS in packet processing of various emulated NICs (CVE-2020-16092
 bsc#1174641)

Fix buffer overflow in the XGMAC device (CVE-2020-15863 bsc#1174386)

Use '%service_del_postun_without_restart' instead of
 '%service_del_postun' to avoid 'Failed to try-restart qemu-ga@.service'
 error while updating the qemu-guest-agent. (bsc#1178565)" );
	script_tag( name: "affected", value: "'qemu' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Manager Proxy 4.0, SUSE Manager Retail Branch Server 4.0, SUSE Manager Server 4.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "qemu", rpm: "qemu~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-arm", rpm: "qemu-arm~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-arm-debuginfo", rpm: "qemu-arm-debuginfo~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-audio-alsa", rpm: "qemu-audio-alsa~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-audio-alsa-debuginfo", rpm: "qemu-audio-alsa-debuginfo~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-audio-oss", rpm: "qemu-audio-oss~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-audio-oss-debuginfo", rpm: "qemu-audio-oss-debuginfo~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-audio-pa", rpm: "qemu-audio-pa~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-audio-pa-debuginfo", rpm: "qemu-audio-pa-debuginfo~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-curl", rpm: "qemu-block-curl~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-curl-debuginfo", rpm: "qemu-block-curl-debuginfo~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-iscsi", rpm: "qemu-block-iscsi~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-iscsi-debuginfo", rpm: "qemu-block-iscsi-debuginfo~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-rbd", rpm: "qemu-block-rbd~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-rbd-debuginfo", rpm: "qemu-block-rbd-debuginfo~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-ssh", rpm: "qemu-block-ssh~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-ssh-debuginfo", rpm: "qemu-block-ssh-debuginfo~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-debuginfo", rpm: "qemu-debuginfo~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-debugsource", rpm: "qemu-debugsource~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-guest-agent", rpm: "qemu-guest-agent~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-guest-agent-debuginfo", rpm: "qemu-guest-agent-debuginfo~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ipxe", rpm: "qemu-ipxe~1.0.0+~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-kvm", rpm: "qemu-kvm~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-lang", rpm: "qemu-lang~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ppc", rpm: "qemu-ppc~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ppc-debuginfo", rpm: "qemu-ppc-debuginfo~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-s390", rpm: "qemu-s390~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-s390-debuginfo", rpm: "qemu-s390-debuginfo~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-seabios", rpm: "qemu-seabios~1.12.0_0_ga698c89~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-sgabios", rpm: "qemu-sgabios~8~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-tools", rpm: "qemu-tools~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-tools-debuginfo", rpm: "qemu-tools-debuginfo~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ui-curses", rpm: "qemu-ui-curses~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ui-curses-debuginfo", rpm: "qemu-ui-curses-debuginfo~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ui-gtk", rpm: "qemu-ui-gtk~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ui-gtk-debuginfo", rpm: "qemu-ui-gtk-debuginfo~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-vgabios", rpm: "qemu-vgabios~1.12.0_0_ga698c89~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-x86", rpm: "qemu-x86~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-x86-debuginfo", rpm: "qemu-x86-debuginfo~3.1.1.1~9.24.3", rls: "SLES15.0SP1" ) )){
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

