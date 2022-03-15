if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2018.1062" );
	script_cve_id( "CVE-2017-8421", "CVE-2018-6323" );
	script_tag( name: "creation_date", value: "2020-01-23 11:11:11 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-31 01:15:00 +0000 (Thu, 31 Oct 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for binutils (EulerOS-SA-2018-1062)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP1" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2018-1062" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1062" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'binutils' package(s) announced via the EulerOS-SA-2018-1062 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The function coff_set_alignment_hook in coffcode.h in Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.28, has a memory leak vulnerability which can cause memory exhaustion in objdump via a crafted PE file. Additional validation in dump_relocs_in_section in objdump.c can resolve this.(CVE-2017-8421)

The elf_object_p function in elfcode.h in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29.1, has an unsigned integer overflow because bfd_size_type multiplication is not used. A crafted ELF file allows remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact.(CVE-2018-6323)" );
	script_tag( name: "affected", value: "'binutils' package(s) on Huawei EulerOS V2.0SP1." );
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
if(release == "EULEROS-2.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "binutils", rpm: "binutils~2.23.52.0.1~55.h10", rls: "EULEROS-2.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "binutils-devel", rpm: "binutils-devel~2.23.52.0.1~55.h10", rls: "EULEROS-2.0SP1" ) )){
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

