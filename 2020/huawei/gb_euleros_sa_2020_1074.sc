if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1074" );
	script_cve_id( "CVE-2018-1000876", "CVE-2018-18309", "CVE-2018-18605", "CVE-2018-18606", "CVE-2018-18607", "CVE-2018-20002", "CVE-2018-20671", "CVE-2019-1010180", "CVE-2019-12972", "CVE-2019-17450", "CVE-2019-17451" );
	script_tag( name: "creation_date", value: "2020-01-23 13:19:35 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for binutils (EulerOS-SA-2020-1074)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRTARM64\\-3\\.0\\.5\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1074" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1074" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'binutils' package(s) announced via the EulerOS-SA-2020-1074 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "GNU gdb All versions is affected by: Buffer Overflow - Out of bound memory access. The impact is: Deny of Service, Memory Disclosure, and Possible Code Execution. The component is: The main gdb module. The attack vector is: Open an ELF for debugging. The fixed version is: Not fixed yet.(CVE-2019-1010180)

The _bfd_generic_read_minisymbols function in syms.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.31, has a memory leak via a crafted ELF file, leading to a denial of service (memory consumption), as demonstrated by nm.(CVE-2018-20002)

binutils version 2.32 and earlier contains a Integer Overflow vulnerability in objdump, bfd_get_dynamic_reloc_upper_bound, bfd_canonicalize_dynamic_reloc that can result in Integer overflow trigger heap overflow. Successful exploitation allows execution of arbitrary code. This attack appear to be exploitable via Local. This vulnerability appears to have been fixed in after commit 3a551c7a1b80fca579461774860574eabfd7f18f.(CVE-2018-1000876)

An issue was discovered in the merge_strings function in merge.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.31. There is a NULL pointer dereference in _bfd_add_merge_section when attempting to merge sections with large alignments. A specially crafted ELF allows remote attackers to cause a denial of service, as demonstrated by ld.(CVE-2018-18606)

An issue was discovered in elf_link_input_bfd in elflink.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.31. There is a NULL pointer dereference in elf_link_input_bfd when used for finding STT_TLS symbols without any TLS section. A specially crafted ELF allows remote attackers to cause a denial of service, as demonstrated by ld.(CVE-2018-18607)

A heap-based buffer over-read issue was discovered in the function sec_merge_hash_lookup in merge.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.31, because _bfd_add_merge_section mishandles section merges when size is not a multiple of entsize. A specially crafted ELF allows remote attackers to cause a denial of service, as demonstrated by ld.(CVE-2018-18605)

An issue was discovered in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.31. An invalid memory address dereference was discovered in read_reloc in reloc.c. The vulnerability causes a segmentation fault and application crash, which leads to denial of service, as demonstrated by objdump, because of missing _bfd_clear_contents bounds checking.(CVE-2018-18309)

An issue was discovered in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.32. It is an integer overflow leading to a SEGV in _bfd_dwarf2_find_nearest_line in dwarf2.c, as demonstrated by nm.(CVE-2019-17451)

find_abstract_instance in dwarf2.c in ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'binutils' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.5.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "binutils", rpm: "binutils~2.31.1~13.h12.eulerosv2r8", rls: "EULEROSVIRTARM64-3.0.5.0" ) )){
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

