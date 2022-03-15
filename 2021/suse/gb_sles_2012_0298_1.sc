if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2012.0298.1" );
	script_cve_id( "CVE-2011-3026" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:28 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-16 16:37:00 +0000 (Thu, 16 Apr 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2012:0298-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP4|SLES11\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2012:0298-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2012/suse-su-20120298-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Mozilla XULrunner' package(s) announced via the SUSE-SU-2012:0298-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla XULRunner was updated to 1.9.2.27 to fix a security issue with the embedded libpng, where a integer overflow could allow remote attackers to crash the browser or potentially execute code (CVE-2011-3026),

Security Issue reference:

 * CVE-2011-3026
>" );
	script_tag( name: "affected", value: "'Mozilla XULrunner' package(s) on SLE SDK 10 SP4, SUSE Linux Enterprise Desktop 10 SP4, SUSE Linux Enterprise Desktop 11 SP1, SUSE Linux Enterprise Server 10 SP4, SUSE Linux Enterprise Server 11 SP1, SUSE Linux Enterprise Software Development Kit 11 SP1." );
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
if(release == "SLES10.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~3.6.27~0.5.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations", rpm: "MozillaFirefox-translations~3.6.27~0.5.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-xulrunner192", rpm: "mozilla-xulrunner192~1.9.2.27~0.5.6", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-xulrunner192-32bit", rpm: "mozilla-xulrunner192-32bit~1.9.2.27~0.5.6", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-xulrunner192-gnome", rpm: "mozilla-xulrunner192-gnome~1.9.2.27~0.5.6", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-xulrunner192-gnome-32bit", rpm: "mozilla-xulrunner192-gnome-32bit~1.9.2.27~0.5.6", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-xulrunner192-translations", rpm: "mozilla-xulrunner192-translations~1.9.2.27~0.5.6", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-xulrunner192-translations-32bit", rpm: "mozilla-xulrunner192-translations-32bit~1.9.2.27~0.5.6", rls: "SLES10.0SP4" ) )){
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
if(release == "SLES11.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "mozilla-xulrunner192", rpm: "mozilla-xulrunner192~1.9.2.27~0.2.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-xulrunner192-32bit", rpm: "mozilla-xulrunner192-32bit~1.9.2.27~0.2.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-xulrunner192-gnome", rpm: "mozilla-xulrunner192-gnome~1.9.2.27~0.2.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-xulrunner192-translations", rpm: "mozilla-xulrunner192-translations~1.9.2.27~0.2.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mozilla-xulrunner192-x86", rpm: "mozilla-xulrunner192-x86~1.9.2.27~0.2.1", rls: "SLES11.0SP1" ) )){
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
