if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.881989" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-08-21 10:09:36 +0200 (Thu, 21 Aug 2014)" );
	script_cve_id( "CVE-2014-0222", "CVE-2014-0223" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "CentOS Update for qemu-guest-agent CESA-2014:1075 centos6" );
	script_tag( name: "summary", value: "Check the version of qemu-guest-agent" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "KVM (Kernel-based Virtual Machine) is a
full virtualization solution for Linux on AMD64 and Intel 64 systems. The qemu-kvm
package provides the user-space component for running virtual machines using KVM.

Two integer overflow flaws were found in the QEMU block driver for QCOW
version 1 disk images. A user able to alter the QEMU disk image files
loaded by a guest could use either of these flaws to corrupt QEMU process
memory on the host, which could potentially result in arbitrary code
execution on the host with the privileges of the QEMU process.
(CVE-2014-0222, CVE-2014-0223)

Red Hat would like to thank NSA for reporting these issues.

This update also fixes the following bugs:

  * In certain scenarios, when performing live incremental migration, the
disk size could be expanded considerably due to the transfer of unallocated
sectors past the end of the base image. With this update, the
bdrv_is_allocated() function has been fixed to no longer return 'True' for
unallocated sectors, and the disk size no longer changes after performing
live incremental migration. (BZ#1109715)

  * This update enables ioeventfd in virtio-scsi-pci. This allows QEMU to
process I/O requests outside of the vCPU thread, reducing the latency of
submitting requests and improving single task throughput. (BZ#1123271)

  * Prior to this update, vendor-specific SCSI commands issued from a KVM
guest did not reach the target device due to QEMU considering such commands
as invalid. This update fixes this bug by properly propagating
vendor-specific SCSI commands to the target device. (BZ#1125131)

All qemu-kvm users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing this
update, shut down all running virtual machines. Once all virtual machines
have shut down, start them again for this update to take effect." );
	script_tag( name: "affected", value: "qemu-guest-agent on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2014:1075" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2014-August/020501.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	exit( 0 );
}
require("pkg-lib-rpm.inc.sc");
require("revisions-lib.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "qemu-guest-agent", rpm: "qemu-guest-agent~0.12.1.2~2.415.el6_5.14", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qemu-img", rpm: "qemu-img~0.12.1.2~2.415.el6_5.14", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qemu-kvm", rpm: "qemu-kvm~0.12.1.2~2.415.el6_5.14", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qemu-kvm-tools", rpm: "qemu-kvm-tools~0.12.1.2~2.415.el6_5.14", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

