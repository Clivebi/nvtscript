if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.0266.1" );
	script_cve_id( "CVE-2019-15691", "CVE-2019-15692", "CVE-2019-15693", "CVE-2019-15694", "CVE-2019-15695" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-21 22:15:00 +0000 (Tue, 21 Jan 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:0266-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:0266-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20200266-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tigervnc' package(s) announced via the SUSE-SU-2020:0266-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for tigervnc provides the following fixes:

Security issues fixed:
CVE-2019-15691: Fixed a use-after-return due to incorrect usage of stack
 memory in ZRLEDecoder (bsc#1159856).

CVE-2019-15692: Fixed a heap-based buffer overflow in CopyRectDecode
 (bsc#1160250).

CVE-2019-15693: Fixed a heap-based buffer overflow in
 TightDecoder::FilterGradient (bsc#1159858).

CVE-2019-15694: Fixed a heap-based buffer overflow, caused by improper
 error handling in processing MemOutStream (bsc#1160251).

CVE-2019-15695: Fixed a stack-based buffer overflow, which could be
 triggered from CMsgReader::readSetCursor (bsc#1159860).

Non-security issue fixed:
Make sure CN in generated certificate doesn't exceed 64 characters.
 (bnc#1041847)

Change with-vnc-key.sh to generate TLS certificate using current
 hostname to keep it short. (bsc#1041847)

Disable MIT-SHM extension when running under user 'vnc'. (bsc#1053373)" );
	script_tag( name: "affected", value: "'tigervnc' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP1." );
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "tigervnc", rpm: "tigervnc~1.4.3~25.11.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tigervnc-debuginfo", rpm: "tigervnc-debuginfo~1.4.3~25.11.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tigervnc-debugsource", rpm: "tigervnc-debugsource~1.4.3~25.11.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-Xvnc", rpm: "xorg-x11-Xvnc~1.4.3~25.11.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-Xvnc-debuginfo", rpm: "xorg-x11-Xvnc-debuginfo~1.4.3~25.11.1", rls: "SLES12.0SP1" ) )){
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

