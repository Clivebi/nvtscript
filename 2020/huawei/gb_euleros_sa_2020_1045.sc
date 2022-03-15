if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1045" );
	script_cve_id( "CVE-2019-14865" );
	script_tag( name: "creation_date", value: "2020-01-23 13:18:03 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-17 14:36:00 +0000 (Mon, 17 May 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for grub2 (EulerOS-SA-2020-1045)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRTARM64\\-3\\.0\\.5\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1045" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1045" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'grub2' package(s) announced via the EulerOS-SA-2020-1045 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A flaw was found in the grub2-set-bootflag utility of grub2. A local attacker could run this utility under resource pressure (for example by setting RLIMIT), causing grub2 configuration files to be truncated and leaving the system unbootable on subsequent reboots.(CVE-2019-14865)" );
	script_tag( name: "affected", value: "'grub2' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.5.0." );
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
if(release == "EULEROSVIRTARM64-3.0.5.0"){
	if(!isnull( res = isrpmvuln( pkg: "grub2-common", rpm: "grub2-common~2.02~62.h15.eulerosv2r8", rls: "EULEROSVIRTARM64-3.0.5.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-efi-aa64", rpm: "grub2-efi-aa64~2.02~62.h15.eulerosv2r8", rls: "EULEROSVIRTARM64-3.0.5.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-efi-aa64-modules", rpm: "grub2-efi-aa64-modules~2.02~62.h15.eulerosv2r8", rls: "EULEROSVIRTARM64-3.0.5.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-tools", rpm: "grub2-tools~2.02~62.h15.eulerosv2r8", rls: "EULEROSVIRTARM64-3.0.5.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-tools-extra", rpm: "grub2-tools-extra~2.02~62.h15.eulerosv2r8", rls: "EULEROSVIRTARM64-3.0.5.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-tools-minimal", rpm: "grub2-tools-minimal~2.02~62.h15.eulerosv2r8", rls: "EULEROSVIRTARM64-3.0.5.0" ) )){
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

