if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.2039.1" );
	script_cve_id( "CVE-2018-12029" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:42 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-08 14:12:00 +0000 (Fri, 08 Mar 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:2039-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:2039-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20182039-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rubygem-passenger' package(s) announced via the SUSE-SU-2018:2039-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for rubygem-passenger fixes the following issue:
The following security vulnerability was addressed:
- CVE-2018-12029: Fixed a file system access race condition in the chown
 command, which allowed for local privilege escalation and affects the
 Nginx module (bsc#1097663)." );
	script_tag( name: "affected", value: "'rubygem-passenger' package(s) on SUSE Linux Enterprise Module for Containers 12." );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "ruby2.1-rubygem-passenger", rpm: "ruby2.1-rubygem-passenger~5.0.18~12.9.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.1-rubygem-passenger-debuginfo", rpm: "ruby2.1-rubygem-passenger-debuginfo~5.0.18~12.9.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-passenger", rpm: "rubygem-passenger~5.0.18~12.9.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-passenger-apache2", rpm: "rubygem-passenger-apache2~5.0.18~12.9.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-passenger-apache2-debuginfo", rpm: "rubygem-passenger-apache2-debuginfo~5.0.18~12.9.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-passenger-debuginfo", rpm: "rubygem-passenger-debuginfo~5.0.18~12.9.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-passenger-debugsource", rpm: "rubygem-passenger-debugsource~5.0.18~12.9.1", rls: "SLES12.0" ) )){
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

