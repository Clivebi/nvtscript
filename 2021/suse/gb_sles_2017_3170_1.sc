if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.3170.1" );
	script_cve_id( "CVE-2014-9939", "CVE-2017-12448", "CVE-2017-12450", "CVE-2017-12452", "CVE-2017-12453", "CVE-2017-12454", "CVE-2017-12456", "CVE-2017-12799", "CVE-2017-13757", "CVE-2017-14128", "CVE-2017-14129", "CVE-2017-14130", "CVE-2017-14333", "CVE-2017-14529", "CVE-2017-14729", "CVE-2017-14745", "CVE-2017-14974", "CVE-2017-6965", "CVE-2017-6966", "CVE-2017-6969", "CVE-2017-7209", "CVE-2017-7210", "CVE-2017-7223", "CVE-2017-7224", "CVE-2017-7225", "CVE-2017-7226", "CVE-2017-7227", "CVE-2017-7299", "CVE-2017-7300", "CVE-2017-7301", "CVE-2017-7302", "CVE-2017-7303", "CVE-2017-7304", "CVE-2017-7614", "CVE-2017-8392", "CVE-2017-8393", "CVE-2017-8394", "CVE-2017-8395", "CVE-2017-8396", "CVE-2017-8397", "CVE-2017-8398", "CVE-2017-8421", "CVE-2017-9038", "CVE-2017-9039", "CVE-2017-9040", "CVE-2017-9041", "CVE-2017-9042", "CVE-2017-9043", "CVE-2017-9044", "CVE-2017-9746", "CVE-2017-9747", "CVE-2017-9748", "CVE-2017-9750", "CVE-2017-9755", "CVE-2017-9756", "CVE-2017-9954", "CVE-2017-9955" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-03-22 19:12:00 +0000 (Wed, 22 Mar 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:3170-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2|SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:3170-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20173170-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'binutils' package(s) announced via the SUSE-SU-2017:3170-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "GNU binutil was updated to the 2.29.1 release, bringing various new features, fixing a lot of bugs and security issues.
Following security issues are being addressed by this release:
 * 18750 bsc#1030296 CVE-2014-9939
 * 20891 bsc#1030585 CVE-2017-7225
 * 20892 bsc#1030588 CVE-2017-7224
 * 20898 bsc#1030589 CVE-2017-7223
 * 20905 bsc#1030584 CVE-2017-7226
 * 20908 bsc#1031644 CVE-2017-7299
 * 20909 bsc#1031656 CVE-2017-7300
 * 20921 bsc#1031595 CVE-2017-7302
 * 20922 bsc#1031593 CVE-2017-7303
 * 20924 bsc#1031638 CVE-2017-7301
 * 20931 bsc#1031590 CVE-2017-7304
 * 21135 bsc#1030298 CVE-2017-7209
 * 21137 bsc#1029909 CVE-2017-6965
 * 21139 bsc#1029908 CVE-2017-6966
 * 21156 bsc#1029907 CVE-2017-6969
 * 21157 bsc#1030297 CVE-2017-7210
 * 21409 bsc#1037052 CVE-2017-8392
 * 21412 bsc#1037057 CVE-2017-8393
 * 21414 bsc#1037061 CVE-2017-8394
 * 21432 bsc#1037066 CVE-2017-8396
 * 21440 bsc#1037273 CVE-2017-8421
 * 21580 bsc#1044891 CVE-2017-9746
 * 21581 bsc#1044897 CVE-2017-9747
 * 21582 bsc#1044901 CVE-2017-9748
 * 21587 bsc#1044909 CVE-2017-9750
 * 21594 bsc#1044925 CVE-2017-9755
 * 21595 bsc#1044927 CVE-2017-9756
 * 21787 bsc#1052518 CVE-2017-12448
 * 21813 bsc#1052503, CVE-2017-12456, bsc#1052507, CVE-2017-12454,
 bsc#1052509, CVE-2017-12453, bsc#1052511, CVE-2017-12452, bsc#1052514,
 CVE-2017-12450, bsc#1052503, CVE-2017-12456, bsc#1052507,
 CVE-2017-12454, bsc#1052509, CVE-2017-12453, bsc#1052511,
 CVE-2017-12452, bsc#1052514, CVE-2017-12450
 * 21933 bsc#1053347 CVE-2017-12799
 * 21990 bsc#1058480 CVE-2017-14333
 * 22018 bsc#1056312 CVE-2017-13757
 * 22047 bsc#1057144 CVE-2017-14129
 * 22058 bsc#1057149 CVE-2017-14130
 * 22059 bsc#1057139 CVE-2017-14128
 * 22113 bsc#1059050 CVE-2017-14529
 * 22148 bsc#1060599 CVE-2017-14745
 * 22163 bsc#1061241 CVE-2017-14974
 * 22170 bsc#1060621 CVE-2017-14729 Update to binutils 2.29. [fate#321454, fate#321494, fate#323293]:
 * The MIPS port now supports microMIPS eXtended Physical Addressing
 (XPA) instructions for assembly and disassembly.
 * The MIPS port now supports the microMIPS Release 5 ISA for assembly
 and disassembly.
 * The MIPS port now supports the Imagination interAptiv MR2 processor,
 which implements the MIPS32r3 ISA, the MIPS16e2 ASE as well as a couple
 of implementation-specific regular MIPS and MIPS16e2 ASE instructions.
 * The SPARC port now supports the SPARC M8 processor, which implements
 the Oracle SPARC Architecture 2017.
 * The MIPS port now supports the MIPS16e2 ASE for assembly and
 disassembly.
 * Add support for ELF SHF_GNU_MBIND and PT_GNU_MBIND_XXX.
 * Add support for the wasm32 ELF conversion of the WebAssembly file
 format.
 * Add --inlines option to objdump, which extends the --line-numbers
 option so that inlined functions will display their nesting
 information.
 * Add --merge-notes options to objcopy to reduce the size of notes in a
 binary file by merging and deleting redundant notes.
 * Add ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'binutils' package(s) on OpenStack Cloud Magnum Orchestration 7, SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP3." );
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "binutils", rpm: "binutils~2.29.1~9.20.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "binutils-debuginfo", rpm: "binutils-debuginfo~2.29.1~9.20.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "binutils-debugsource", rpm: "binutils-debugsource~2.29.1~9.20.2", rls: "SLES12.0SP2" ) )){
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "binutils", rpm: "binutils~2.29.1~9.20.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "binutils-debuginfo", rpm: "binutils-debuginfo~2.29.1~9.20.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "binutils-debugsource", rpm: "binutils-debugsource~2.29.1~9.20.2", rls: "SLES12.0SP3" ) )){
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

