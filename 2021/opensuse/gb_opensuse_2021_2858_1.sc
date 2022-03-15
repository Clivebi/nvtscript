if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854120" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2020-35503", "CVE-2020-35504", "CVE-2020-35505", "CVE-2020-35506", "CVE-2021-20255", "CVE-2021-3527", "CVE-2021-3682" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-17 17:29:00 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-28 01:02:16 +0000 (Sat, 28 Aug 2021)" );
	script_name( "openSUSE: Security Advisory for qemu (openSUSE-SU-2021:2858-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:2858-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GGOXRRBMGRJGBNXEGPCZ3JFLXCMIM6A3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu'
  package(s) announced via the openSUSE-SU-2021:2858-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for qemu fixes the following issues:

     Security issues fixed:

  - usbredir: free call on invalid pointer in bufp_alloc (bsc#1189145,
       CVE-2021-3682)

  - NULL pointer dereference in ESP (bsc#1180433, CVE-2020-35504)
       (bsc#1180434, CVE-2020-35505) (bsc#1180435, CVE-2020-35506)

  - NULL pointer dereference issue in megasas-gen2 host bus adapter
       (bsc#1180432, CVE-2020-35503)

  - eepro100: stack overflow via infinite recursion (bsc#1182651,
       CVE-2021-20255)

  - usb: unbounded stack allocation in usbredir (bsc#1186012, CVE-2021-3527)

     Non-security issues fixed:

  - Use max host physical address if -cpu max is used (bsc#1188299)" );
	script_tag( name: "affected", value: "'qemu' package(s) on openSUSE Leap 15.3." );
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
if(release == "openSUSELeap15.3"){
	if(!isnull( res = isrpmvuln( pkg: "qemu", rpm: "qemu~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-arm", rpm: "qemu-arm~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-arm-debuginfo", rpm: "qemu-arm-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-audio-alsa", rpm: "qemu-audio-alsa~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-audio-alsa-debuginfo", rpm: "qemu-audio-alsa-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-audio-pa", rpm: "qemu-audio-pa~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-audio-pa-debuginfo", rpm: "qemu-audio-pa-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-audio-spice", rpm: "qemu-audio-spice~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-audio-spice-debuginfo", rpm: "qemu-audio-spice-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-curl", rpm: "qemu-block-curl~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-curl-debuginfo", rpm: "qemu-block-curl-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-dmg", rpm: "qemu-block-dmg~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-dmg-debuginfo", rpm: "qemu-block-dmg-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-gluster", rpm: "qemu-block-gluster~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-gluster-debuginfo", rpm: "qemu-block-gluster-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-iscsi", rpm: "qemu-block-iscsi~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-iscsi-debuginfo", rpm: "qemu-block-iscsi-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-nfs", rpm: "qemu-block-nfs~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-nfs-debuginfo", rpm: "qemu-block-nfs-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-rbd", rpm: "qemu-block-rbd~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-rbd-debuginfo", rpm: "qemu-block-rbd-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-ssh", rpm: "qemu-block-ssh~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-ssh-debuginfo", rpm: "qemu-block-ssh-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-chardev-baum", rpm: "qemu-chardev-baum~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-chardev-baum-debuginfo", rpm: "qemu-chardev-baum-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-chardev-spice", rpm: "qemu-chardev-spice~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-chardev-spice-debuginfo", rpm: "qemu-chardev-spice-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-debuginfo", rpm: "qemu-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-debugsource", rpm: "qemu-debugsource~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-extra", rpm: "qemu-extra~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-extra-debuginfo", rpm: "qemu-extra-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-guest-agent", rpm: "qemu-guest-agent~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-guest-agent-debuginfo", rpm: "qemu-guest-agent-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-hw-display-qxl", rpm: "qemu-hw-display-qxl~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-hw-display-qxl-debuginfo", rpm: "qemu-hw-display-qxl-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-hw-display-virtio-gpu", rpm: "qemu-hw-display-virtio-gpu~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-hw-display-virtio-gpu-debuginfo", rpm: "qemu-hw-display-virtio-gpu-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-hw-display-virtio-gpu-pci", rpm: "qemu-hw-display-virtio-gpu-pci~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-hw-display-virtio-gpu-pci-debuginfo", rpm: "qemu-hw-display-virtio-gpu-pci-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-hw-display-virtio-vga", rpm: "qemu-hw-display-virtio-vga~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-hw-display-virtio-vga-debuginfo", rpm: "qemu-hw-display-virtio-vga-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-hw-s390x-virtio-gpu-ccw", rpm: "qemu-hw-s390x-virtio-gpu-ccw~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-hw-s390x-virtio-gpu-ccw-debuginfo", rpm: "qemu-hw-s390x-virtio-gpu-ccw-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-hw-usb-redirect", rpm: "qemu-hw-usb-redirect~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-hw-usb-redirect-debuginfo", rpm: "qemu-hw-usb-redirect-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-hw-usb-smartcard", rpm: "qemu-hw-usb-smartcard~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-hw-usb-smartcard-debuginfo", rpm: "qemu-hw-usb-smartcard-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ivshmem-tools", rpm: "qemu-ivshmem-tools~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ivshmem-tools-debuginfo", rpm: "qemu-ivshmem-tools-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ksm", rpm: "qemu-ksm~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-lang", rpm: "qemu-lang~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ppc", rpm: "qemu-ppc~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ppc-debuginfo", rpm: "qemu-ppc-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-s390x", rpm: "qemu-s390x~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-s390x-debuginfo", rpm: "qemu-s390x-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-tools", rpm: "qemu-tools~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-tools-debuginfo", rpm: "qemu-tools-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ui-curses", rpm: "qemu-ui-curses~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ui-curses-debuginfo", rpm: "qemu-ui-curses-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ui-gtk", rpm: "qemu-ui-gtk~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ui-gtk-debuginfo", rpm: "qemu-ui-gtk-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ui-opengl", rpm: "qemu-ui-opengl~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ui-opengl-debuginfo", rpm: "qemu-ui-opengl-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ui-spice-app", rpm: "qemu-ui-spice-app~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ui-spice-app-debuginfo", rpm: "qemu-ui-spice-app-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ui-spice-core", rpm: "qemu-ui-spice-core~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ui-spice-core-debuginfo", rpm: "qemu-ui-spice-core-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-vhost-user-gpu", rpm: "qemu-vhost-user-gpu~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-vhost-user-gpu-debuginfo", rpm: "qemu-vhost-user-gpu-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-x86", rpm: "qemu-x86~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-x86-debuginfo", rpm: "qemu-x86-debuginfo~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-kvm", rpm: "qemu-kvm~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ipxe", rpm: "qemu-ipxe~1.0.0+~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-microvm", rpm: "qemu-microvm~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-seabios", rpm: "qemu-seabios~1.14.0_0_g155821a~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-sgabios-8", rpm: "qemu-sgabios-8~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-skiboot", rpm: "qemu-skiboot~5.2.0~103.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-vgabios", rpm: "qemu-vgabios~1.14.0_0_g155821a~103.2", rls: "openSUSELeap15.3" ) )){
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

