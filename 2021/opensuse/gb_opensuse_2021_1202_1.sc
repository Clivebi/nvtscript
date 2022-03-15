if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854119" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2020-35503", "CVE-2020-35504", "CVE-2020-35505", "CVE-2020-35506", "CVE-2021-20255", "CVE-2021-3527", "CVE-2021-3582", "CVE-2021-3592", "CVE-2021-3593", "CVE-2021-3594", "CVE-2021-3595", "CVE-2021-3607", "CVE-2021-3608", "CVE-2021-3611", "CVE-2021-3682" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-17 17:29:00 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-27 01:02:05 +0000 (Fri, 27 Aug 2021)" );
	script_name( "openSUSE: Security Advisory for qemu (openSUSE-SU-2021:1202-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1202-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7XTOHNMISPT4N5NUXQJPKV5LQNNGSMFI" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu'
  package(s) announced via the openSUSE-SU-2021:1202-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for qemu fixes the following issues:

     Security issues fixed:

  - CVE-2021-3527: usb: unbounded stack allocation in usbredir (bsc#1186012)

  - CVE-2021-3582: Fix possible mremap overflow in the pvrdma (bsc#1187499)

  - CVE-2021-3592: Fix for slirp: invalid pointer initialization may lead to
       information disclosure (bootp) (bsc#1187364)

  - CVE-2021-3593: Fix for slirp: invalid pointer initialization may lead to
       information disclosure (udp6) (bsc#1187365)

  - CVE-2021-3594: Fix for slirp: invalid pointer initialization may lead to
       information disclosure (udp) (bsc#1187367)

  - CVE-2021-3595: Fixed slirp: invalid pointer initialization may lead to
       information disclosure (tftp) (bsc#1187366)

  - CVE-2021-3607: Ensure correct input on ring init (bsc#1187539)

  - CVE-2021-3608: Fix the ring init error flow (bsc#1187538)

  - CVE-2021-3611: Fix intel-hda segmentation fault due to stack overflow
       (bsc#1187529)

  - CVE-2021-3682: usbredir: free call on invalid pointer in bufp_alloc
       (bsc#1189145)

  - CVE-2020-35503: NULL pointer dereference issue in megasas-gen2 host bus
       adapter (bsc#1180432)

  - CVE-2020-35504, CVE-2020-35505, CVE-2020-35506: NULL pointer dereference
       in ESP (bsc#1180433 bsc#1180434 bsc#1180435)

  - CVE-2021-20255: eepro100: stack overflow via infinite recursion
       (bsc#1182651)

     This update was imported from the SUSE:SLE-15-SP2:Update update project." );
	script_tag( name: "affected", value: "'qemu' package(s) on openSUSE Leap 15.2." );
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
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "qemu", rpm: "qemu~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-arm", rpm: "qemu-arm~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-arm-debuginfo", rpm: "qemu-arm-debuginfo~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-audio-alsa", rpm: "qemu-audio-alsa~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-audio-alsa-debuginfo", rpm: "qemu-audio-alsa-debuginfo~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-audio-pa", rpm: "qemu-audio-pa~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-audio-pa-debuginfo", rpm: "qemu-audio-pa-debuginfo~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-audio-sdl", rpm: "qemu-audio-sdl~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-audio-sdl-debuginfo", rpm: "qemu-audio-sdl-debuginfo~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-curl", rpm: "qemu-block-curl~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-curl-debuginfo", rpm: "qemu-block-curl-debuginfo~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-dmg", rpm: "qemu-block-dmg~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-dmg-debuginfo", rpm: "qemu-block-dmg-debuginfo~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-gluster", rpm: "qemu-block-gluster~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-gluster-debuginfo", rpm: "qemu-block-gluster-debuginfo~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-iscsi", rpm: "qemu-block-iscsi~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-iscsi-debuginfo", rpm: "qemu-block-iscsi-debuginfo~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-nfs", rpm: "qemu-block-nfs~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-nfs-debuginfo", rpm: "qemu-block-nfs-debuginfo~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-rbd", rpm: "qemu-block-rbd~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-rbd-debuginfo", rpm: "qemu-block-rbd-debuginfo~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-ssh", rpm: "qemu-block-ssh~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-ssh-debuginfo", rpm: "qemu-block-ssh-debuginfo~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-debuginfo", rpm: "qemu-debuginfo~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-debugsource", rpm: "qemu-debugsource~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-extra", rpm: "qemu-extra~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-extra-debuginfo", rpm: "qemu-extra-debuginfo~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-guest-agent", rpm: "qemu-guest-agent~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-guest-agent-debuginfo", rpm: "qemu-guest-agent-debuginfo~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ksm", rpm: "qemu-ksm~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-kvm", rpm: "qemu-kvm~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-lang", rpm: "qemu-lang~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-linux-user", rpm: "qemu-linux-user~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-linux-user-debuginfo", rpm: "qemu-linux-user-debuginfo~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-linux-user-debugsource", rpm: "qemu-linux-user-debugsource~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ppc", rpm: "qemu-ppc~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ppc-debuginfo", rpm: "qemu-ppc-debuginfo~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-s390", rpm: "qemu-s390~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-s390-debuginfo", rpm: "qemu-s390-debuginfo~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-testsuite", rpm: "qemu-testsuite~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-tools", rpm: "qemu-tools~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-tools-debuginfo", rpm: "qemu-tools-debuginfo~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ui-curses", rpm: "qemu-ui-curses~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ui-curses-debuginfo", rpm: "qemu-ui-curses-debuginfo~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ui-gtk", rpm: "qemu-ui-gtk~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ui-gtk-debuginfo", rpm: "qemu-ui-gtk-debuginfo~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ui-sdl", rpm: "qemu-ui-sdl~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ui-sdl-debuginfo", rpm: "qemu-ui-sdl-debuginfo~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ui-spice-app", rpm: "qemu-ui-spice-app~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ui-spice-app-debuginfo", rpm: "qemu-ui-spice-app-debuginfo~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-vhost-user-gpu", rpm: "qemu-vhost-user-gpu~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-vhost-user-gpu-debuginfo", rpm: "qemu-vhost-user-gpu-debuginfo~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-x86", rpm: "qemu-x86~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-x86-debuginfo", rpm: "qemu-x86-debuginfo~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ipxe", rpm: "qemu-ipxe~1.0.0+~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-microvm", rpm: "qemu-microvm~4.2.1~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-seabios", rpm: "qemu-seabios~1.12.1+~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-sgabios", rpm: "qemu-sgabios~8~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-vgabios", rpm: "qemu-vgabios~1.12.1+~lp152.9.20.1", rls: "openSUSELeap15.2" ) )){
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

