if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.2462" );
	script_cve_id( "CVE-2020-10713" );
	script_tag( name: "creation_date", value: "2020-11-05 08:49:40 +0000 (Thu, 05 Nov 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-01 02:15:00 +0000 (Sat, 01 May 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for grub2 (EulerOS-SA-2020-2462)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-3\\.0\\.6\\.6" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-2462" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2462" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'grub2' package(s) announced via the EulerOS-SA-2020-2462 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "grub2: Crafted grub.cfg file can lead to arbitrary code execution during boot process (CVE-2020-10713)" );
	script_tag( name: "affected", value: "'grub2' package(s) on Huawei EulerOS Virtualization 3.0.6.6." );
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
if(release == "EULEROSVIRT-3.0.6.6"){
	if(!isnull( res = isrpmvuln( pkg: "grub2", rpm: "grub2~2.02~0.65.2.h15.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-common", rpm: "grub2-common~2.02~0.65.2.h15.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-efi-x64", rpm: "grub2-efi-x64~2.02~0.65.2.h15.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-efi-x64-cdboot", rpm: "grub2-efi-x64-cdboot~2.02~0.65.2.h15.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-efi-x64-modules", rpm: "grub2-efi-x64-modules~2.02~0.65.2.h15.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-pc", rpm: "grub2-pc~2.02~0.65.2.h15.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-pc-modules", rpm: "grub2-pc-modules~2.02~0.65.2.h15.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-tools", rpm: "grub2-tools~2.02~0.65.2.h15.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-tools-extra", rpm: "grub2-tools-extra~2.02~0.65.2.h15.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-tools-minimal", rpm: "grub2-tools-minimal~2.02~0.65.2.h15.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
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

