if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1197" );
	script_cve_id( "CVE-2012-6703", "CVE-2013-3076", "CVE-2013-3231", "CVE-2013-3237", "CVE-2018-13406", "CVE-2018-18386" );
	script_tag( name: "creation_date", value: "2020-01-23 11:34:12 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)" );
	script_name( "Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1197)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.5\\.3" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1197" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1197" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2019-1197 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A security flaw was found in the Linux kernel in drivers/tty/n_tty.c which allows local attackers (ones who are able to access pseudo terminals) to lock them up and block further usage of any pseudo terminal devices due to an EXTPROC versus ICANON confusion in TIOCINQ handler.(CVE-2018-18386)

The Linux kernel was found vulnerable to an integer overflow in the drivers/video/fbdev/uvesafb.c:uvesafb_setcmap() function. The vulnerability could result in local attackers being able to crash the kernel or potentially elevate privileges.(CVE-2018-13406)

The vsock_stream_sendmsg function in net/vmw_vsock/af_vsock.c in the Linux kernel before 3.9-rc7 does not initialize a certain length variable, which allows local users to obtain sensitive information from kernel stack memory via a crafted recvmsg or recvfrom system call.(CVE-2013-3237)

The llc_ui_recvmsg function in net/llc/af_llc.c in the Linux kernel before 3.9-rc7 does not initialize a certain length variable, which allows local users to obtain sensitive information from kernel stack memory via a crafted recvmsg or recvfrom system call.(CVE-2013-3231)

The crypto API in the Linux kernel through 3.9-rc8 does not initialize certain length variables, which allows local users to obtain sensitive information from kernel stack memory via a crafted recvmsg or recvfrom system call, related to the hash_recvmsg function in crypto/algif_hash.c and the skcipher_recvmsg function in crypto/algif_skcipher.c.(CVE-2013-3076)

Integer overflow in the snd_compr_allocate_buffer function in sound/core/compress_offload.c in the ALSA subsystem in the Linux kernel before 3.6-rc6-next-20120917 allows local users to cause a denial of service (insufficient memory allocation) or possibly have unspecified other impact via a crafted SNDRV_COMPRESS_SET_PARAMS ioctl call.(CVE-2012-6703)" );
	script_tag( name: "affected", value: "'kernel' package(s) on Huawei EulerOS Virtualization 2.5.3." );
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
if(release == "EULEROSVIRT-2.5.3"){
	if(!isnull( res = isrpmvuln( pkg: "kernel", rpm: "kernel~3.10.0~514.44.5.10_117", rls: "EULEROSVIRT-2.5.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~3.10.0~514.44.5.10_117", rls: "EULEROSVIRT-2.5.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~3.10.0~514.44.5.10_117", rls: "EULEROSVIRT-2.5.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools", rpm: "kernel-tools~3.10.0~514.44.5.10_117", rls: "EULEROSVIRT-2.5.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools-libs", rpm: "kernel-tools-libs~3.10.0~514.44.5.10_117", rls: "EULEROSVIRT-2.5.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools-libs-devel", rpm: "kernel-tools-libs-devel~3.10.0~514.44.5.10_117", rls: "EULEROSVIRT-2.5.3" ) )){
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

