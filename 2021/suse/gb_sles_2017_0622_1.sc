if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.0622.1" );
	script_cve_id( "CVE-2016-10207", "CVE-2016-9941", "CVE-2016-9942" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-23 13:15:00 +0000 (Fri, 23 Oct 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:0622-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:0622-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20170622-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tigervnc' package(s) announced via the SUSE-SU-2017:0622-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for tigervnc provides the following fixes:
- Prevent malicious server from crashing a server via a buffer overflow, a
 similar flaw as the LibVNCServer issues CVE-2016-9941 and CVE-2016-9942.
 (bsc#1019274)
- CVE-2016-10207: Prevent potential crash due to insufficient clean-up
 after failure to establish TLS connection. (bsc#1023012)" );
	script_tag( name: "affected", value: "'tigervnc' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "libXvnc1", rpm: "libXvnc1~1.6.0~16.4", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libXvnc1-debuginfo", rpm: "libXvnc1-debuginfo~1.6.0~16.4", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tigervnc", rpm: "tigervnc~1.6.0~16.4", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tigervnc-debuginfo", rpm: "tigervnc-debuginfo~1.6.0~16.4", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tigervnc-debugsource", rpm: "tigervnc-debugsource~1.6.0~16.4", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-Xvnc", rpm: "xorg-x11-Xvnc~1.6.0~16.4", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-Xvnc-debuginfo", rpm: "xorg-x11-Xvnc-debuginfo~1.6.0~16.4", rls: "SLES12.0SP2" ) )){
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

