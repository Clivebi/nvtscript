if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882637" );
	script_version( "2021-09-13T12:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 12:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-19 05:41:53 +0100 (Thu, 19 Jan 2017)" );
	script_cve_id( "CVE-2016-2857" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 14:45:00 +0000 (Thu, 15 Oct 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for qemu-img CESA-2017:0083 centos7" );
	script_tag( name: "summary", value: "Check the version of qemu-img" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Kernel-based Virtual Machine (KVM) is
a full virtualization solution for Linux on AMD64 and Intel 64 systems.
The qemu-kvm packages provide the user-space component for running virtual
machines using KVM.

Security Fix(es):

  * An out-of-bounds read-access flaw was found in the QEMU emulator built
with IP checksum routines. The flaw could occur when computing a TCP/UDP
packet's checksum, because a QEMU function used the packet's payload length
without checking against the data buffer's size. A user inside a guest
could use this flaw to crash the QEMU process (denial of service).
(CVE-2016-2857)

Red Hat would like to thank Ling Liu (Qihoo 360 Inc.) for reporting this
issue.

Bug Fix(es):

  * Previously, rebooting a guest virtual machine more than 128 times in a
short period of time caused the guest to shut down instead of rebooting,
because the virtqueue was not cleaned properly. This update ensures that
the virtqueue is cleaned more reliably, which prevents the described
problem from occurring. (BZ#1393484)" );
	script_tag( name: "affected", value: "qemu-img on CentOS 7" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2017:0083" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2017-January/022227.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "qemu-img", rpm: "qemu-img~1.5.3~126.el7_3.3", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qemu-kvm", rpm: "qemu-kvm~1.5.3~126.el7_3.3", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qemu-kvm-common", rpm: "qemu-kvm-common~1.5.3~126.el7_3.3", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qemu-kvm-tools", rpm: "qemu-kvm-tools~1.5.3~126.el7_3.3", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

