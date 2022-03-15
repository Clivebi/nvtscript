if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.0766.1" );
	script_cve_id( "CVE-2018-12181", "CVE-2019-0160" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-06 17:15:00 +0000 (Tue, 06 Aug 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:0766-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:0766-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20190766-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ovmf' package(s) announced via the SUSE-SU-2019:0766-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ovmf fixes the following issues:

Security issues fixed:
CVE-2019-0160: Fixed multiple buffer overflows in UDF-related codes in
 MdeModulePkg\\Universal\\Disk\\PartitionDxe\\Udf.c and
 MdeModulePkg\\Universal\\Disk\\UdfDxe (bsc#1130267).

CVE-2018-12181: Fixed a stack buffer overflow in the HII database when a
 corrupted Bitmap was used (bsc#1128503)." );
	script_tag( name: "affected", value: "'ovmf' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4." );
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "ovmf", rpm: "ovmf~2017+git1510945757.b2662641d5~3.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ovmf-tools", rpm: "ovmf-tools~2017+git1510945757.b2662641d5~3.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ovmf-x86_64", rpm: "qemu-ovmf-x86_64~2017+git1510945757.b2662641d5~3.13.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-uefi-aarch64", rpm: "qemu-uefi-aarch64~2017+git1510945757.b2662641d5~3.13.1", rls: "SLES12.0SP4" ) )){
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

