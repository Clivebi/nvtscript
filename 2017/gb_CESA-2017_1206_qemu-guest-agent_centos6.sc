if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882712" );
	script_version( "2021-09-13T14:16:31+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 14:16:31 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-10 06:53:28 +0200 (Wed, 10 May 2017)" );
	script_cve_id( "CVE-2016-9603", "CVE-2017-2633", "CVE-2017-7718", "CVE-2017-7980" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-07 10:29:00 +0000 (Fri, 07 Sep 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for qemu-guest-agent CESA-2017:1206 centos6" );
	script_tag( name: "summary", value: "Check the version of qemu-guest-agent" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Kernel-based Virtual Machine (KVM) is a
full virtualization solution for Linux on a variety of architectures.
The qemu-kvm package provides the user-space component for running virtual
machines that use KVM.

Security Fix(es):

  * A heap buffer overflow flaw was found in QEMU's Cirrus CLGD 54xx VGA
emulator's VNC display driver support  the issue could occur when a VNC
client attempted to update its display after a VGA operation is performed
by a guest. A privileged user/process inside a guest could use this flaw to
crash the QEMU process or, potentially, execute arbitrary code on the host
with privileges of the QEMU process. (CVE-2016-9603)

  * An out-of-bounds r/w access issue was found in QEMU's Cirrus CLGD 54xx
VGA Emulator support. The vulnerability could occur while copying VGA data
via various bitblt functions. A privileged user inside a guest could use
this flaw to crash the QEMU process or, potentially, execute arbitrary code
on the host with privileges of the QEMU process. (CVE-2017-7980)

  * An out-of-bounds memory access issue was found in QEMU's VNC display
driver support. The vulnerability could occur while refreshing the VNC
display surface area in the 'vnc_refresh_server_surface'. A user/process
inside a guest could use this flaw to crash the QEMU process, resulting in
a denial of service. (CVE-2017-2633)

  * An out-of-bounds access issue was found in QEMU's Cirrus CLGD 54xx VGA
Emulator support. The vulnerability could occur while copying VGA data
using bitblt functions (for example, cirrus_bitblt_rop_fwd_transp_). A
privileged user inside a guest could use this flaw to crash the QEMU
process, resulting in denial of service. (CVE-2017-7718)

Red Hat would like to thank Jiangxin (PSIRT Huawei Inc.) and Li Qiang
(Qihoo 360 Gear Team) for reporting CVE-2017-7980 and Jiangxin (PSIRT
Huawei Inc.) for reporting CVE-2017-7718.

4. Solution: For details on how to apply this update, which includes the changes
described in this advisory see the references. After installing this update, shut
down all running virtual machines. Once all virtual machines have shut down, start
them again for this update to take effect." );
	script_tag( name: "affected", value: "qemu-guest-agent on CentOS 6" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2017:1206" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2017-May/022403.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_xref( name: "URL", value: "https://access.redhat.com/articles/11258" );
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
	if(( res = isrpmvuln( pkg: "qemu-guest-agent", rpm: "qemu-guest-agent~0.12.1.2~2.503.el6_9.3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qemu-img", rpm: "qemu-img~0.12.1.2~2.503.el6_9.3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qemu-kvm", rpm: "qemu-kvm~0.12.1.2~2.503.el6_9.3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qemu-kvm-tools", rpm: "qemu-kvm-tools~0.12.1.2~2.503.el6_9.3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

