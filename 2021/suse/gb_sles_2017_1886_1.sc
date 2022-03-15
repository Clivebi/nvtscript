if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.1886.1" );
	script_cve_id( "CVE-2017-6891", "CVE-2017-7869" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:55 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:1886-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:1886-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20171886-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnutls' package(s) announced via the SUSE-SU-2017:1886-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for gnutls fixes the following issues:
- GNUTLS-SA-2017-3 / CVE-2017-7869: An out-of-bounds write in OpenPGP
 certificate decoding was fixed (bsc#1034173)
- CVE-2017-6891: A potential stack buffer overflow in the bundled libtasn1
 was fixed (bsc#1040621)
- An address read of 4 bytes past the end of buffer in OpenPGP certificate
 parsing was fixed (bsc#1038337)" );
	script_tag( name: "affected", value: "'gnutls' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise High Availability Extension 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "gnutls", rpm: "gnutls~2.4.1~24.39.70.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls-extra26", rpm: "libgnutls-extra26~2.4.1~24.39.70.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls26", rpm: "libgnutls26~2.4.1~24.39.70.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls26-32bit", rpm: "libgnutls26-32bit~2.4.1~24.39.70.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls26-x86", rpm: "libgnutls26-x86~2.4.1~24.39.70.1", rls: "SLES11.0SP4" ) )){
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

