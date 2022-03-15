if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882539" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-08-10 05:35:04 +0200 (Wed, 10 Aug 2016)" );
	script_cve_id( "CVE-2016-5403" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for qemu-guest-agent CESA-2016:1585 centos6" );
	script_tag( name: "summary", value: "Check the version of qemu-guest-agent" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "KVM (Kernel-based Virtual Machine) is a
full virtualization solution for Linux on AMD64 and Intel 64 systems.
The qemu-kvm packages provide the user-space component for running virtual machines
using KVM.

Security Fix(es):

  * Quick emulator(Qemu) built with the virtio framework is vulnerable to an
unbounded memory allocation issue. It was found that a malicious guest user
could submit more requests than the virtqueue size permits. Processing a
request allocates a VirtQueueElement and therefore causes unbounded memory
allocation on the host controlled by the guest. (CVE-2016-5403)

Red Hat would like to thank hongzhenhao (Marvel Team) for reporting this
issue." );
	script_tag( name: "affected", value: "qemu-guest-agent on CentOS 6" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:1585" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-August/022030.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "qemu-guest-agent", rpm: "qemu-guest-agent~0.12.1.2~2.491.el6_8.3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qemu-img", rpm: "qemu-img~0.12.1.2~2.491.el6_8.3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qemu-kvm", rpm: "qemu-kvm~0.12.1.2~2.491.el6_8.3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qemu-kvm-tools", rpm: "qemu-kvm-tools~0.12.1.2~2.491.el6_8.3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

