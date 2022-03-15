if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.2304.1" );
	script_cve_id( "CVE-2018-3639" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-14 14:51:00 +0000 (Wed, 14 Apr 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:2304-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:2304-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20182304-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvirt' package(s) announced via the SUSE-SU-2018:2304-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libvirt fixes the following issues:
Security issue fixed:
- CVE-2018-3639: Add support for 'ssbd' and 'virt-ssbd' CPUID feature bits
 to address V4 Speculative Store Bypass aka 'Memory Disambiguation'
 (bsc#1092885).
Bug fixes:
- bsc#1094325: Enable virsh blockresize for XEN guests (FATE#325467).
- bsc#1095556: Fix qemu VM creating with --boot uefi due to missing
 AppArmor profile.
- bsc#1094725: Fix `virsh blockresize` to work with Xen qdisks.
- bsc#1094480: Fix `virsh list` to list domains with `xl list`.
- bsc#1087416: Fix missing video device within guest with default
 installation by virt-mamanger.
- bsc#1079150: Fix libvirt-guests start dependency.
- bsc#1076861: Fix locking of lockspace resource
 '/devcfs/disks/uatidmsvn1-xvda'.
- bsc#1074014: Fix KVM live migration when shutting down cluster node.
- bsc#959329: Fix wrong state of VMs in virtual manager." );
	script_tag( name: "affected", value: "'libvirt' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "libvirt", rpm: "libvirt~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-admin", rpm: "libvirt-admin~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-admin-debuginfo", rpm: "libvirt-admin-debuginfo~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-client", rpm: "libvirt-client~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-client-debuginfo", rpm: "libvirt-client-debuginfo~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon", rpm: "libvirt-daemon~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-config-network", rpm: "libvirt-daemon-config-network~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-config-nwfilter", rpm: "libvirt-daemon-config-nwfilter~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-debuginfo", rpm: "libvirt-daemon-debuginfo~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-interface", rpm: "libvirt-daemon-driver-interface~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-interface-debuginfo", rpm: "libvirt-daemon-driver-interface-debuginfo~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-libxl", rpm: "libvirt-daemon-driver-libxl~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-libxl-debuginfo", rpm: "libvirt-daemon-driver-libxl-debuginfo~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-lxc", rpm: "libvirt-daemon-driver-lxc~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-lxc-debuginfo", rpm: "libvirt-daemon-driver-lxc-debuginfo~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-network", rpm: "libvirt-daemon-driver-network~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-network-debuginfo", rpm: "libvirt-daemon-driver-network-debuginfo~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-nodedev", rpm: "libvirt-daemon-driver-nodedev~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-nodedev-debuginfo", rpm: "libvirt-daemon-driver-nodedev-debuginfo~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-nwfilter", rpm: "libvirt-daemon-driver-nwfilter~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-nwfilter-debuginfo", rpm: "libvirt-daemon-driver-nwfilter-debuginfo~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-qemu", rpm: "libvirt-daemon-driver-qemu~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-qemu-debuginfo", rpm: "libvirt-daemon-driver-qemu-debuginfo~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-secret", rpm: "libvirt-daemon-driver-secret~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-secret-debuginfo", rpm: "libvirt-daemon-driver-secret-debuginfo~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage", rpm: "libvirt-daemon-driver-storage~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-core", rpm: "libvirt-daemon-driver-storage-core~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-core-debuginfo", rpm: "libvirt-daemon-driver-storage-core-debuginfo~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-disk", rpm: "libvirt-daemon-driver-storage-disk~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-disk-debuginfo", rpm: "libvirt-daemon-driver-storage-disk-debuginfo~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-iscsi", rpm: "libvirt-daemon-driver-storage-iscsi~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-iscsi-debuginfo", rpm: "libvirt-daemon-driver-storage-iscsi-debuginfo~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-logical", rpm: "libvirt-daemon-driver-storage-logical~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-logical-debuginfo", rpm: "libvirt-daemon-driver-storage-logical-debuginfo~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-mpath", rpm: "libvirt-daemon-driver-storage-mpath~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-mpath-debuginfo", rpm: "libvirt-daemon-driver-storage-mpath-debuginfo~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-rbd", rpm: "libvirt-daemon-driver-storage-rbd~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-rbd-debuginfo", rpm: "libvirt-daemon-driver-storage-rbd-debuginfo~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-scsi", rpm: "libvirt-daemon-driver-storage-scsi~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-scsi-debuginfo", rpm: "libvirt-daemon-driver-storage-scsi-debuginfo~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-hooks", rpm: "libvirt-daemon-hooks~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-lxc", rpm: "libvirt-daemon-lxc~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-qemu", rpm: "libvirt-daemon-qemu~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-xen", rpm: "libvirt-daemon-xen~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-debugsource", rpm: "libvirt-debugsource~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-doc", rpm: "libvirt-doc~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-libs", rpm: "libvirt-libs~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-libs-debuginfo", rpm: "libvirt-libs-debuginfo~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-lock-sanlock", rpm: "libvirt-lock-sanlock~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-lock-sanlock-debuginfo", rpm: "libvirt-lock-sanlock-debuginfo~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-nss", rpm: "libvirt-nss~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-nss-debuginfo", rpm: "libvirt-nss-debuginfo~3.3.0~5.22.1", rls: "SLES12.0SP3" ) )){
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

