if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.1893.1" );
	script_cve_id( "CVE-2017-1000083" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:1893-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:1893-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20171893-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'evince' package(s) announced via the SUSE-SU-2017:1893-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for evince fixes the following issues:
- CVE-2017-1000083: Remote attackers could have used the comicbook mode of
 evince to inject shell code. (bsc#1046856, bgo#784630)" );
	script_tag( name: "affected", value: "'evince' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP2, SUSE Linux Enterprise Workstation Extension 12-SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "evince", rpm: "evince~3.20.1~6.14.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-browser-plugin", rpm: "evince-browser-plugin~3.20.1~6.14.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-browser-plugin-debuginfo", rpm: "evince-browser-plugin-debuginfo~3.20.1~6.14.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-debuginfo", rpm: "evince-debuginfo~3.20.1~6.14.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-debugsource", rpm: "evince-debugsource~3.20.1~6.14.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-lang", rpm: "evince-lang~3.20.1~6.14.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-plugin-djvudocument", rpm: "evince-plugin-djvudocument~3.20.1~6.14.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-plugin-djvudocument-debuginfo", rpm: "evince-plugin-djvudocument-debuginfo~3.20.1~6.14.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-plugin-dvidocument", rpm: "evince-plugin-dvidocument~3.20.1~6.14.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-plugin-dvidocument-debuginfo", rpm: "evince-plugin-dvidocument-debuginfo~3.20.1~6.14.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-plugin-pdfdocument", rpm: "evince-plugin-pdfdocument~3.20.1~6.14.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-plugin-pdfdocument-debuginfo", rpm: "evince-plugin-pdfdocument-debuginfo~3.20.1~6.14.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-plugin-psdocument", rpm: "evince-plugin-psdocument~3.20.1~6.14.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-plugin-psdocument-debuginfo", rpm: "evince-plugin-psdocument-debuginfo~3.20.1~6.14.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-plugin-tiffdocument", rpm: "evince-plugin-tiffdocument~3.20.1~6.14.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-plugin-tiffdocument-debuginfo", rpm: "evince-plugin-tiffdocument-debuginfo~3.20.1~6.14.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-plugin-xpsdocument", rpm: "evince-plugin-xpsdocument~3.20.1~6.14.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "evince-plugin-xpsdocument-debuginfo", rpm: "evince-plugin-xpsdocument-debuginfo~3.20.1~6.14.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libevdocument3-4", rpm: "libevdocument3-4~3.20.1~6.14.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libevdocument3-4-debuginfo", rpm: "libevdocument3-4-debuginfo~3.20.1~6.14.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libevview3-3", rpm: "libevview3-3~3.20.1~6.14.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libevview3-3-debuginfo", rpm: "libevview3-3-debuginfo~3.20.1~6.14.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nautilus-evince", rpm: "nautilus-evince~3.20.1~6.14.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nautilus-evince-debuginfo", rpm: "nautilus-evince-debuginfo~3.20.1~6.14.1", rls: "SLES12.0SP2" ) )){
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

