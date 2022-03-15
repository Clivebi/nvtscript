if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.2392" );
	script_cve_id( "CVE-2014-3689", "CVE-2019-15890", "CVE-2019-20382", "CVE-2020-14364", "CVE-2020-15863" );
	script_tag( name: "creation_date", value: "2020-11-04 08:55:30 +0000 (Wed, 04 Nov 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-20 11:15:00 +0000 (Fri, 20 Sep 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for qemu-kvm (EulerOS-SA-2020-2392)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-2392" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2392" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'qemu-kvm' package(s) announced via the EulerOS-SA-2020-2392 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "QEMU 4.1.0 has a memory leak in zrle_compress_data in ui/vnc-enc-zrle.c during a VNC disconnect operation because libz is misused, resulting in a situation where memory allocated in deflateInit2 is not freed in deflateEnd.(CVE-2019-20382)

libslirp 4.0.0, as used in QEMU 4.1.0, has a use-after-free in ip_reass in ip_input.c.(CVE-2019-15890)

An out-of-bounds read/write access flaw was found in the USB emulator of the QEMU in versions before 5.2.0. This issue occurs while processing USB packets from a guest when USBDevice 'setup_len' exceeds its 'data_buf[4096]' in the do_token_in, do_token_out routines. This flaw allows a guest user to crash the QEMU process, resulting in a denial of service, or the potential execution of arbitrary code with the privileges of the QEMU process on the host.(CVE-2020-14364)

hw/net/xgmac.c in the XGMAC Ethernet controller in QEMU before 07-20-2020 has a buffer overflow. This occurs during packet transmission and affects the highbank and midway emulated machines. A guest user or process could use this flaw to crash the QEMU process on the host, resulting in a denial of service or potential privileged code execution. This was fixed in commit 5519724a13664b43e225ca05351c60b4468e4555.(CVE-2020-15863)

The vmware-vga driver (hw/display/vmware_vga.c) in QEMU allows local guest users to write to qemu memory locations and gain privileges via unspecified parameters related to rectangle handling.(CVE-2014-3689)" );
	script_tag( name: "affected", value: "'qemu-kvm' package(s) on Huawei EulerOS V2.0SP2." );
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
if(release == "EULEROS-2.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "qemu-img", rpm: "qemu-img~1.5.3~156.5.h35", rls: "EULEROS-2.0SP2" ) )){
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

