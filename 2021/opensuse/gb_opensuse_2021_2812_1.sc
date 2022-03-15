if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854103" );
	script_version( "2021-08-24T09:58:36+0000" );
	script_cve_id( "CVE-2021-3631", "CVE-2021-3667" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-24 09:58:36 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-24 03:01:47 +0000 (Tue, 24 Aug 2021)" );
	script_name( "openSUSE: Security Advisory for libvirt (openSUSE-SU-2021:2812-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:2812-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/K4QAQWSVV2PRNPOI4R3VBPRTRXS5NLQ5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvirt'
  package(s) announced via the openSUSE-SU-2021:2812-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libvirt fixes the following issues:

     Security issues fixed:

  - CVE-2021-3631: fix SELinux label generation logic (bsc#1187871)

  - CVE-2021-3667: Unlock object on ACL fail in
       storagePoolLookupByTargetPath (bsc#1188843)

     Non-security issues fixed:

  - virtlockd: Don&#x27 t report error if lockspace exists (bsc#1184253)

  - Don&#x27 t forcibly remove &#x27 --listen&#x27  arg from /etc/sysconfig/libvirtd.
  Add
       &#x27 --timeout 120&#x27  if &#x27 --listen&#x27  is not specified. (bsc#1188232)" );
	script_tag( name: "affected", value: "'libvirt' package(s) on openSUSE Leap 15.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "libvirt", rpm: "libvirt~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-admin", rpm: "libvirt-admin~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-admin-debuginfo", rpm: "libvirt-admin-debuginfo~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-client", rpm: "libvirt-client~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-client-debuginfo", rpm: "libvirt-client-debuginfo~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon", rpm: "libvirt-daemon~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-config-network", rpm: "libvirt-daemon-config-network~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-config-nwfilter", rpm: "libvirt-daemon-config-nwfilter~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-debuginfo", rpm: "libvirt-daemon-debuginfo~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-interface", rpm: "libvirt-daemon-driver-interface~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-interface-debuginfo", rpm: "libvirt-daemon-driver-interface-debuginfo~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-lxc", rpm: "libvirt-daemon-driver-lxc~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-lxc-debuginfo", rpm: "libvirt-daemon-driver-lxc-debuginfo~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-network", rpm: "libvirt-daemon-driver-network~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-network-debuginfo", rpm: "libvirt-daemon-driver-network-debuginfo~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-nodedev", rpm: "libvirt-daemon-driver-nodedev~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-nodedev-debuginfo", rpm: "libvirt-daemon-driver-nodedev-debuginfo~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-nwfilter", rpm: "libvirt-daemon-driver-nwfilter~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-nwfilter-debuginfo", rpm: "libvirt-daemon-driver-nwfilter-debuginfo~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-qemu", rpm: "libvirt-daemon-driver-qemu~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-qemu-debuginfo", rpm: "libvirt-daemon-driver-qemu-debuginfo~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-secret", rpm: "libvirt-daemon-driver-secret~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-secret-debuginfo", rpm: "libvirt-daemon-driver-secret-debuginfo~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage", rpm: "libvirt-daemon-driver-storage~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-core", rpm: "libvirt-daemon-driver-storage-core~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-core-debuginfo", rpm: "libvirt-daemon-driver-storage-core-debuginfo~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-disk", rpm: "libvirt-daemon-driver-storage-disk~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-disk-debuginfo", rpm: "libvirt-daemon-driver-storage-disk-debuginfo~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-gluster", rpm: "libvirt-daemon-driver-storage-gluster~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-gluster-debuginfo", rpm: "libvirt-daemon-driver-storage-gluster-debuginfo~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-iscsi", rpm: "libvirt-daemon-driver-storage-iscsi~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-iscsi-debuginfo", rpm: "libvirt-daemon-driver-storage-iscsi-debuginfo~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-iscsi-direct", rpm: "libvirt-daemon-driver-storage-iscsi-direct~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-iscsi-direct-debuginfo", rpm: "libvirt-daemon-driver-storage-iscsi-direct-debuginfo~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-logical", rpm: "libvirt-daemon-driver-storage-logical~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-logical-debuginfo", rpm: "libvirt-daemon-driver-storage-logical-debuginfo~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-mpath", rpm: "libvirt-daemon-driver-storage-mpath~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-mpath-debuginfo", rpm: "libvirt-daemon-driver-storage-mpath-debuginfo~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-scsi", rpm: "libvirt-daemon-driver-storage-scsi~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-scsi-debuginfo", rpm: "libvirt-daemon-driver-storage-scsi-debuginfo~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-hooks", rpm: "libvirt-daemon-hooks~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-lxc", rpm: "libvirt-daemon-lxc~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-qemu", rpm: "libvirt-daemon-qemu~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-debugsource", rpm: "libvirt-debugsource~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-devel", rpm: "libvirt-devel~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-libs", rpm: "libvirt-libs~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-libs-debuginfo", rpm: "libvirt-libs-debuginfo~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-lock-sanlock", rpm: "libvirt-lock-sanlock~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-lock-sanlock-debuginfo", rpm: "libvirt-lock-sanlock-debuginfo~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-nss", rpm: "libvirt-nss~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-nss-debuginfo", rpm: "libvirt-nss-debuginfo~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark-plugin-libvirt", rpm: "wireshark-plugin-libvirt~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark-plugin-libvirt-debuginfo", rpm: "wireshark-plugin-libvirt-debuginfo~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-rbd", rpm: "libvirt-daemon-driver-storage-rbd~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-rbd-debuginfo", rpm: "libvirt-daemon-driver-storage-rbd-debuginfo~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-bash-completion", rpm: "libvirt-bash-completion~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-doc", rpm: "libvirt-doc~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-client-32bit-debuginfo", rpm: "libvirt-client-32bit-debuginfo~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-libxl", rpm: "libvirt-daemon-driver-libxl~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-libxl-debuginfo", rpm: "libvirt-daemon-driver-libxl-debuginfo~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-xen", rpm: "libvirt-daemon-xen~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-devel-32bit", rpm: "libvirt-devel-32bit~7.1.0~6.5.1", rls: "openSUSELeap15.3" ) )){
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

