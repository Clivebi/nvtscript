if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2014.0576.1" );
	script_cve_id( "CVE-2014-1912" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:21 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-25 11:53:00 +0000 (Fri, 25 Oct 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2014:0576-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2014:0576-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2014/suse-su-20140576-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Python' package(s) announced via the SUSE-SU-2014:0576-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Python was updated to fix a security issue in the socket.recvfrom_into function, where data could be written over the end of the buffer. (CVE-2014-1912)

Security Issue reference:

 * CVE-2014-1912
>" );
	script_tag( name: "affected", value: "'Python' package(s) on SUSE Linux Enterprise Desktop 11 SP3, SUSE Linux Enterprise Server 11 SP3, SUSE Linux Enterprise Software Development Kit 11 SP3." );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "libpython2_6-1_0", rpm: "libpython2_6-1_0~2.6.9~0.27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython2_6-1_0-32bit", rpm: "libpython2_6-1_0-32bit~2.6.9~0.27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython2_6-1_0-x86", rpm: "libpython2_6-1_0-x86~2.6.9~0.27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python", rpm: "python~2.6.9~0.27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-32bit", rpm: "python-32bit~2.6.9~0.27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base", rpm: "python-base~2.6.9~0.27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-32bit", rpm: "python-base-32bit~2.6.9~0.27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-x86", rpm: "python-base-x86~2.6.9~0.27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-curses", rpm: "python-curses~2.6.9~0.27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-demo", rpm: "python-demo~2.6.9~0.27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-doc", rpm: "python-doc~2.6~8.27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-doc-pdf", rpm: "python-doc-pdf~2.6~8.27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-gdbm", rpm: "python-gdbm~2.6.9~0.27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-idle", rpm: "python-idle~2.6.9~0.27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-tk", rpm: "python-tk~2.6.9~0.27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-x86", rpm: "python-x86~2.6.9~0.27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-xml", rpm: "python-xml~2.6.9~0.27.1", rls: "SLES11.0SP3" ) )){
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
