if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.2810.1" );
	script_cve_id( "CVE-2020-12049" );
	script_tag( name: "creation_date", value: "2021-08-24 02:30:09 +0000 (Tue, 24 Aug 2021)" );
	script_version( "2021-08-24T02:30:09+0000" );
	script_tag( name: "last_modification", value: "2021-08-24 02:30:09 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-04 21:17:00 +0000 (Thu, 04 Mar 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:2810-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP2|SLES15\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:2810-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20212810-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dbus-1' package(s) announced via the SUSE-SU-2021:2810-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for dbus-1 fixes the following issues:

CVE-2020-12049: truncated messages lead to resource exhaustion.
 (bsc#1172505)" );
	script_tag( name: "affected", value: "'dbus-1' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE MicroOS 5.0." );
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
if(release == "SLES15.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "dbus-1", rpm: "dbus-1~1.12.2~8.11.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-1-32bit-debuginfo", rpm: "dbus-1-32bit-debuginfo~1.12.2~8.11.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-1-debuginfo", rpm: "dbus-1-debuginfo~1.12.2~8.11.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-1-debugsource", rpm: "dbus-1-debugsource~1.12.2~8.11.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-1-devel", rpm: "dbus-1-devel~1.12.2~8.11.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-1-x11", rpm: "dbus-1-x11~1.12.2~8.11.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-1-x11-debuginfo", rpm: "dbus-1-x11-debuginfo~1.12.2~8.11.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-1-x11-debugsource", rpm: "dbus-1-x11-debugsource~1.12.2~8.11.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdbus-1-3", rpm: "libdbus-1-3~1.12.2~8.11.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdbus-1-3-32bit", rpm: "libdbus-1-3-32bit~1.12.2~8.11.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdbus-1-3-32bit-debuginfo", rpm: "libdbus-1-3-32bit-debuginfo~1.12.2~8.11.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdbus-1-3-debuginfo", rpm: "libdbus-1-3-debuginfo~1.12.2~8.11.2", rls: "SLES15.0SP2" ) )){
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
if(release == "SLES15.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "dbus-1", rpm: "dbus-1~1.12.2~8.11.2", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-1-32bit-debuginfo", rpm: "dbus-1-32bit-debuginfo~1.12.2~8.11.2", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-1-debuginfo", rpm: "dbus-1-debuginfo~1.12.2~8.11.2", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-1-debugsource", rpm: "dbus-1-debugsource~1.12.2~8.11.2", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-1-devel", rpm: "dbus-1-devel~1.12.2~8.11.2", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-1-x11", rpm: "dbus-1-x11~1.12.2~8.11.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-1-x11-debuginfo", rpm: "dbus-1-x11-debuginfo~1.12.2~8.11.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-1-x11-debugsource", rpm: "dbus-1-x11-debugsource~1.12.2~8.11.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdbus-1-3", rpm: "libdbus-1-3~1.12.2~8.11.2", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdbus-1-3-32bit", rpm: "libdbus-1-3-32bit~1.12.2~8.11.2", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdbus-1-3-32bit-debuginfo", rpm: "libdbus-1-3-32bit-debuginfo~1.12.2~8.11.2", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdbus-1-3-debuginfo", rpm: "libdbus-1-3-debuginfo~1.12.2~8.11.2", rls: "SLES15.0SP3" ) )){
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
