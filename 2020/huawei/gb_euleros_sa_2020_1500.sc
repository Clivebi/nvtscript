if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1500" );
	script_cve_id( "CVE-2017-5898" );
	script_tag( name: "creation_date", value: "2020-04-16 05:58:56 +0000 (Thu, 16 Apr 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-10 18:55:00 +0000 (Tue, 10 Nov 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for qemu-kvm (EulerOS-SA-2020-1500)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-3\\.0\\.2\\.2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1500" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1500" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'qemu-kvm' package(s) announced via the EulerOS-SA-2020-1500 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Integer overflow in the emulated_apdu_from_guest function in usb/dev-smartcard-reader.c in Quick Emulator (Qemu), when built with the CCID Card device emulator support, allows local users to cause a denial of service (application crash) via a large Application Protocol Data Units (APDU) unit.(CVE-2017-5898)" );
	script_tag( name: "affected", value: "'qemu-kvm' package(s) on Huawei EulerOS Virtualization 3.0.2.2." );
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
if(release == "EULEROSVIRT-3.0.2.2"){
	if(!isnull( res = isrpmvuln( pkg: "qemu-gpu-specs", rpm: "qemu-gpu-specs~2.8.1~30.079", rls: "EULEROSVIRT-3.0.2.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-guest-agent", rpm: "qemu-guest-agent~2.8.1~30.079", rls: "EULEROSVIRT-3.0.2.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-img", rpm: "qemu-img~2.8.1~30.079", rls: "EULEROSVIRT-3.0.2.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-kvm", rpm: "qemu-kvm~2.8.1~30.079", rls: "EULEROSVIRT-3.0.2.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-kvm-common", rpm: "qemu-kvm-common~2.8.1~30.079", rls: "EULEROSVIRT-3.0.2.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-kvm-tools", rpm: "qemu-kvm-tools~2.8.1~30.079", rls: "EULEROSVIRT-3.0.2.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-seabios", rpm: "qemu-seabios~2.8.1~30.079", rls: "EULEROSVIRT-3.0.2.2" ) )){
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

