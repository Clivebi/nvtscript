if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853763" );
	script_version( "2021-08-26T09:01:14+0000" );
	script_cve_id( "CVE-2019-15945", "CVE-2019-15946", "CVE-2019-19479", "CVE-2019-19480", "CVE-2019-20792", "CVE-2020-26570", "CVE-2020-26571", "CVE-2020-26572" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 09:01:14 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-26 16:51:00 +0000 (Tue, 26 May 2020)" );
	script_tag( name: "creation_date", value: "2021-04-17 03:00:53 +0000 (Sat, 17 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for opensc (openSUSE-SU-2021:0565-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0565-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JELZKRVEJGYE74DM3GTNHNTVZBQHK5DJ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'opensc'
  package(s) announced via the openSUSE-SU-2021:0565-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for opensc fixes the following issues:

  - CVE-2019-15945: Fixed an out-of-bounds access of an ASN.1 Bitstring in
       decode_bit_string (bsc#1149746).

  - CVE-2019-15946: Fixed an out-of-bounds access of an ASN.1 Octet string
       in asn1_decode_entry (bsc#1149747)

  - CVE-2019-19479: Fixed an incorrect read operation during parsing of a
       SETCOS file attribute (bsc#1158256)

  - CVE-2019-19480: Fixed an improper free operation in
       sc_pkcs15_decode_prkdf_entry (bsc#1158307).

  - CVE-2019-20792: Fixed a double free in coolkey_free_private_data
       (bsc#1170809).

  - CVE-2020-26570: Fixed a buffer overflow in sc_oberthur_read_file
       (bsc#1177364).

  - CVE-2020-26571: Fixed a stack-based buffer overflow in gemsafe GPK smart
       card software driver (bsc#1177380)

  - CVE-2020-26572: Fixed a stack-based buffer overflow in tcos_decipher
       (bsc#1177378).

     This update was imported from the SUSE:SLE-15-SP1:Update update project." );
	script_tag( name: "affected", value: "'opensc' package(s) on openSUSE Leap 15.2." );
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
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "opensc", rpm: "opensc~0.19.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "opensc-debuginfo", rpm: "opensc-debuginfo~0.19.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "opensc-debugsource", rpm: "opensc-debugsource~0.19.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "opensc-32bit", rpm: "opensc-32bit~0.19.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "opensc-32bit-debuginfo", rpm: "opensc-32bit-debuginfo~0.19.0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
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

