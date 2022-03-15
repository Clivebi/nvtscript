if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.1316.1" );
	script_cve_id( "CVE-2015-5477" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:11 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-10 02:29:00 +0000 (Fri, 10 Nov 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:1316-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:1316-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20151316-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bind' package(s) announced via the SUSE-SU-2015:1316-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "bind was updated to fix one security issue.
This security issue was fixed:
- CVE-2015-5477: Remote DoS via TKEY queries (bsc#939567)
Exposure to this issue can not be prevented by either ACLs or configuration options limiting or denying service because the exploitable code occurs early in the packet handling." );
	script_tag( name: "affected", value: "'bind' package(s) on SUSE Linux Enterprise Server 11-SP1." );
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
if(release == "SLES11.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "bind", rpm: "bind~9.6ESVR11W1~0.6.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-chrootenv", rpm: "bind-chrootenv~9.6ESVR11W1~0.6.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-devel", rpm: "bind-devel~9.6ESVR11W1~0.6.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-doc", rpm: "bind-doc~9.6ESVR11W1~0.6.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs-32bit", rpm: "bind-libs-32bit~9.6ESVR11W1~0.6.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-libs", rpm: "bind-libs~9.6ESVR11W1~0.6.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-utils", rpm: "bind-utils~9.6ESVR11W1~0.6.1", rls: "SLES11.0SP1" ) )){
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

