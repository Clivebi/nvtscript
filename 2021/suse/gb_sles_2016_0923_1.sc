if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.0923.1" );
	script_cve_id( "CVE-2015-5313" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:0923-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:0923-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20160923-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvirt' package(s) announced via the SUSE-SU-2016:0923-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update to libvirt 1.2.18.2 fixes the following minor security issue:
- CVE-2015-5313: Directory traversal allowed privilege escalation
 (bsc#953110)
The following bugs were fixed:
- bsc#952849: Don't add apparmor deny rw rule for 9P readonly mounts.
- bsc#960305: libxl: support parsing and formatting vif bandwidth
- bsc#954872: libxl: Add support for block-{dmmd,drbd,npiv} scripts
- bsc#964465: Remove 'Wants=xencommons.service' from libvirtd service file" );
	script_tag( name: "affected", value: "'libvirt' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP1, SUSE Linux Enterprise Workstation Extension 12-SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "libvirt", rpm: "libvirt~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-client", rpm: "libvirt-client~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-client-debuginfo", rpm: "libvirt-client-debuginfo~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon", rpm: "libvirt-daemon~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-config-network", rpm: "libvirt-daemon-config-network~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-config-nwfilter", rpm: "libvirt-daemon-config-nwfilter~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-debuginfo", rpm: "libvirt-daemon-debuginfo~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-interface", rpm: "libvirt-daemon-driver-interface~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-interface-debuginfo", rpm: "libvirt-daemon-driver-interface-debuginfo~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-libxl", rpm: "libvirt-daemon-driver-libxl~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-libxl-debuginfo", rpm: "libvirt-daemon-driver-libxl-debuginfo~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-lxc", rpm: "libvirt-daemon-driver-lxc~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-lxc-debuginfo", rpm: "libvirt-daemon-driver-lxc-debuginfo~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-network", rpm: "libvirt-daemon-driver-network~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-network-debuginfo", rpm: "libvirt-daemon-driver-network-debuginfo~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-nodedev", rpm: "libvirt-daemon-driver-nodedev~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-nodedev-debuginfo", rpm: "libvirt-daemon-driver-nodedev-debuginfo~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-nwfilter", rpm: "libvirt-daemon-driver-nwfilter~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-nwfilter-debuginfo", rpm: "libvirt-daemon-driver-nwfilter-debuginfo~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-qemu", rpm: "libvirt-daemon-driver-qemu~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-qemu-debuginfo", rpm: "libvirt-daemon-driver-qemu-debuginfo~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-secret", rpm: "libvirt-daemon-driver-secret~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-secret-debuginfo", rpm: "libvirt-daemon-driver-secret-debuginfo~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage", rpm: "libvirt-daemon-driver-storage~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-debuginfo", rpm: "libvirt-daemon-driver-storage-debuginfo~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-lxc", rpm: "libvirt-daemon-lxc~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-qemu", rpm: "libvirt-daemon-qemu~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-xen", rpm: "libvirt-daemon-xen~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-debugsource", rpm: "libvirt-debugsource~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-doc", rpm: "libvirt-doc~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-lock-sanlock", rpm: "libvirt-lock-sanlock~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-lock-sanlock-debuginfo", rpm: "libvirt-lock-sanlock-debuginfo~1.2.18.2~8.1", rls: "SLES12.0SP1" ) )){
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

