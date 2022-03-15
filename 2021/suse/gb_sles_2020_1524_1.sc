if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.1524.1" );
	script_cve_id( "CVE-2019-18348", "CVE-2019-9674", "CVE-2020-8492" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-27 18:15:00 +0000 (Mon, 27 Jul 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:1524-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP1|SLES12\\.0SP2|SLES12\\.0SP3|SLES12\\.0SP4|SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:1524-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20201524-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python' package(s) announced via the SUSE-SU-2020:1524-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python to version 2.7.17 fixes the following issues:

Syncing with lots of upstream bug fixes and security fixes.

Bug fixes:

CVE-2019-9674: Improved the documentation to reflect the dangers of
 zip-bombs (bsc#1162825).

CVE-2019-18348: Fixed a CRLF injection via the host part of the url
 passed to urlopen(). Now an InvalidURL exception is raised (bsc#1155094).

CVE-2020-8492: Fixed a regular expression in urllib that was prone to
 denial of service via HTTP (bsc#1162367).

Fixed mismatches between libpython and python-base versions
 (bsc#1162224).

Fixed segfault in libpython2.7.so.1 (bsc#1073748).

Unified packages among openSUSE:Factory and SLE versions (bsc#1159035).

Added idle.desktop and idle.appdata.xml to provide IDLE in menus
 (bsc#1153830).

Excluded tsl_check files from python-base to prevent file conflict with
 python-strict-tls-checks package (bsc#945401).

Changed the name of idle3 icons to idle3.png to avoid collision with
 Python 2 version (bsc#1165894).

Additionally a new 'shared-python-startup' package is provided containing startup files.

python-rpm-macros was updated to fix:

Do not write .pyc files for tests (bsc#1171561)" );
	script_tag( name: "affected", value: "'python' package(s) on HPE Helion Openstack 8, SUSE Enterprise Storage 5, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12-SP4, SUSE Linux Enterprise Workstation Extension 12-SP5, SUSE OpenStack Cloud 7, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud Crowbar 8." );
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
	if(!isnull( res = isrpmvuln( pkg: "libpython2_7-1_0", rpm: "libpython2_7-1_0~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython2_7-1_0-32bit", rpm: "libpython2_7-1_0-32bit~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython2_7-1_0-debuginfo", rpm: "libpython2_7-1_0-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython2_7-1_0-debuginfo-32bit", rpm: "libpython2_7-1_0-debuginfo-32bit~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python", rpm: "python~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-32bit", rpm: "python-32bit~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base", rpm: "python-base~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-32bit", rpm: "python-base-32bit~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-debuginfo", rpm: "python-base-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-debuginfo-32bit", rpm: "python-base-debuginfo-32bit~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-debugsource", rpm: "python-base-debugsource~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-curses", rpm: "python-curses~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-curses-debuginfo", rpm: "python-curses-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-debuginfo", rpm: "python-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-debuginfo-32bit", rpm: "python-debuginfo-32bit~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-debugsource", rpm: "python-debugsource~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-demo", rpm: "python-demo~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-devel", rpm: "python-devel~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-doc", rpm: "python-doc~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-doc-pdf", rpm: "python-doc-pdf~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-gdbm", rpm: "python-gdbm~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-gdbm-debuginfo", rpm: "python-gdbm-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-idle", rpm: "python-idle~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rpm-macros", rpm: "python-rpm-macros~20200207.5feb6c1~3.19.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-tk", rpm: "python-tk~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-tk-debuginfo", rpm: "python-tk-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-xml", rpm: "python-xml~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-xml-debuginfo", rpm: "python-xml-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "shared-python-startup", rpm: "shared-python-startup~0.1~1.3.1", rls: "SLES12.0SP1" ) )){
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "libpython2_7-1_0", rpm: "libpython2_7-1_0~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython2_7-1_0-32bit", rpm: "libpython2_7-1_0-32bit~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython2_7-1_0-debuginfo", rpm: "libpython2_7-1_0-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython2_7-1_0-debuginfo-32bit", rpm: "libpython2_7-1_0-debuginfo-32bit~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python", rpm: "python~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-32bit", rpm: "python-32bit~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base", rpm: "python-base~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-32bit", rpm: "python-base-32bit~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-debuginfo", rpm: "python-base-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-debuginfo-32bit", rpm: "python-base-debuginfo-32bit~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-debugsource", rpm: "python-base-debugsource~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-curses", rpm: "python-curses~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-curses-debuginfo", rpm: "python-curses-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-debuginfo", rpm: "python-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-debuginfo-32bit", rpm: "python-debuginfo-32bit~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-debugsource", rpm: "python-debugsource~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-demo", rpm: "python-demo~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-devel", rpm: "python-devel~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-doc", rpm: "python-doc~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-doc-pdf", rpm: "python-doc-pdf~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-gdbm", rpm: "python-gdbm~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-gdbm-debuginfo", rpm: "python-gdbm-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-idle", rpm: "python-idle~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rpm-macros", rpm: "python-rpm-macros~20200207.5feb6c1~3.19.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-tk", rpm: "python-tk~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-tk-debuginfo", rpm: "python-tk-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-xml", rpm: "python-xml~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-xml-debuginfo", rpm: "python-xml-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "shared-python-startup", rpm: "shared-python-startup~0.1~1.3.1", rls: "SLES12.0SP2" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "libpython2_7-1_0", rpm: "libpython2_7-1_0~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython2_7-1_0-32bit", rpm: "libpython2_7-1_0-32bit~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython2_7-1_0-debuginfo", rpm: "libpython2_7-1_0-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython2_7-1_0-debuginfo-32bit", rpm: "libpython2_7-1_0-debuginfo-32bit~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python", rpm: "python~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-32bit", rpm: "python-32bit~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base", rpm: "python-base~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-32bit", rpm: "python-base-32bit~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-debuginfo", rpm: "python-base-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-debuginfo-32bit", rpm: "python-base-debuginfo-32bit~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-debugsource", rpm: "python-base-debugsource~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-curses", rpm: "python-curses~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-curses-debuginfo", rpm: "python-curses-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-debuginfo", rpm: "python-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-debuginfo-32bit", rpm: "python-debuginfo-32bit~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-debugsource", rpm: "python-debugsource~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-demo", rpm: "python-demo~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-devel", rpm: "python-devel~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-doc", rpm: "python-doc~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-doc-pdf", rpm: "python-doc-pdf~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-gdbm", rpm: "python-gdbm~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-gdbm-debuginfo", rpm: "python-gdbm-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-idle", rpm: "python-idle~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rpm-macros", rpm: "python-rpm-macros~20200207.5feb6c1~3.19.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-tk", rpm: "python-tk~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-tk-debuginfo", rpm: "python-tk-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-xml", rpm: "python-xml~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-xml-debuginfo", rpm: "python-xml-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "shared-python-startup", rpm: "shared-python-startup~0.1~1.3.1", rls: "SLES12.0SP3" ) )){
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "libpython2_7-1_0", rpm: "libpython2_7-1_0~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython2_7-1_0-32bit", rpm: "libpython2_7-1_0-32bit~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython2_7-1_0-debuginfo", rpm: "libpython2_7-1_0-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython2_7-1_0-debuginfo-32bit", rpm: "libpython2_7-1_0-debuginfo-32bit~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python", rpm: "python~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-32bit", rpm: "python-32bit~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base", rpm: "python-base~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-32bit", rpm: "python-base-32bit~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-debuginfo", rpm: "python-base-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-debuginfo-32bit", rpm: "python-base-debuginfo-32bit~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-debugsource", rpm: "python-base-debugsource~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-curses", rpm: "python-curses~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-curses-debuginfo", rpm: "python-curses-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-debuginfo", rpm: "python-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-debuginfo-32bit", rpm: "python-debuginfo-32bit~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-debugsource", rpm: "python-debugsource~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-demo", rpm: "python-demo~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-devel", rpm: "python-devel~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-doc", rpm: "python-doc~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-doc-pdf", rpm: "python-doc-pdf~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-gdbm", rpm: "python-gdbm~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-gdbm-debuginfo", rpm: "python-gdbm-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-idle", rpm: "python-idle~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rpm-macros", rpm: "python-rpm-macros~20200207.5feb6c1~3.19.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-tk", rpm: "python-tk~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-tk-debuginfo", rpm: "python-tk-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-xml", rpm: "python-xml~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-xml-debuginfo", rpm: "python-xml-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "shared-python-startup", rpm: "shared-python-startup~0.1~1.3.1", rls: "SLES12.0SP4" ) )){
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
if(release == "SLES12.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "libpython2_7-1_0", rpm: "libpython2_7-1_0~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython2_7-1_0-32bit", rpm: "libpython2_7-1_0-32bit~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython2_7-1_0-debuginfo", rpm: "libpython2_7-1_0-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython2_7-1_0-debuginfo-32bit", rpm: "libpython2_7-1_0-debuginfo-32bit~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python", rpm: "python~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-32bit", rpm: "python-32bit~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base", rpm: "python-base~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-32bit", rpm: "python-base-32bit~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-debuginfo", rpm: "python-base-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-debuginfo-32bit", rpm: "python-base-debuginfo-32bit~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-debugsource", rpm: "python-base-debugsource~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-curses", rpm: "python-curses~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-curses-debuginfo", rpm: "python-curses-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-debuginfo", rpm: "python-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-debuginfo-32bit", rpm: "python-debuginfo-32bit~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-debugsource", rpm: "python-debugsource~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-demo", rpm: "python-demo~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-devel", rpm: "python-devel~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-doc", rpm: "python-doc~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-doc-pdf", rpm: "python-doc-pdf~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-gdbm", rpm: "python-gdbm~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-gdbm-debuginfo", rpm: "python-gdbm-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-idle", rpm: "python-idle~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-rpm-macros", rpm: "python-rpm-macros~20200207.5feb6c1~3.19.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-tk", rpm: "python-tk~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-tk-debuginfo", rpm: "python-tk-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-xml", rpm: "python-xml~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-xml-debuginfo", rpm: "python-xml-debuginfo~2.7.17~28.42.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "shared-python-startup", rpm: "shared-python-startup~0.1~1.3.1", rls: "SLES12.0SP5" ) )){
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

