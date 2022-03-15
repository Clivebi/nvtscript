if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2018.1400" );
	script_cve_id( "CVE-2018-10372", "CVE-2018-10373", "CVE-2018-10534", "CVE-2018-10535", "CVE-2018-7568", "CVE-2018-7569", "CVE-2018-7642", "CVE-2018-8945" );
	script_tag( name: "creation_date", value: "2020-01-23 11:24:45 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-03 13:15:00 +0000 (Sat, 03 Aug 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for binutils (EulerOS-SA-2018-1400)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP3" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2018-1400" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1400" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'binutils' package(s) announced via the EulerOS-SA-2018-1400 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "binutils: integer overflow via an ELF file with corrupt dwarf1 debug information in libbfd library (CVE-2018-7568)

binutils: integer underflow or overflow via an ELF file with a corrupt DWARF FORM block in libbfd library (CVE-2018-7569)

binutils: NULL pointer dereference in swap_std_reloc_in function in aoutx.h resulting in crash (CVE-2018-7642)

binutils: Crash in elf.c:bfd_section_from_shdr() with crafted executable (CVE-2018-8945)

binutils: Heap-base buffer over-read in dwarf.c:process_cu_tu_index() allows for denial of service via crafted file (CVE-2018-10372)

binutils: NULL pointer dereference in dwarf2.c:concat_filename() allows for denial of service via crafted file (CVE-2018-10373)

binutils: out of bounds memory write in peXXigen.c files (CVE-2018-10534)

binutils: NULL pointer dereference in elf.c (CVE-2018-10535)" );
	script_tag( name: "affected", value: "'binutils' package(s) on Huawei EulerOS V2.0SP3." );
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
if(release == "EULEROS-2.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "binutils", rpm: "binutils~2.25.1~22.base.h17", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "binutils-devel", rpm: "binutils-devel~2.25.1~22.base.h17", rls: "EULEROS-2.0SP3" ) )){
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

