if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.0107.1" );
	script_cve_id( "CVE-2013-6435", "CVE-2014-8118" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-29 11:29:00 +0000 (Thu, 29 Nov 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:0107-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:0107-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20150107-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rpm' package(s) announced via the SUSE-SU-2015:0107-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This rpm update fixes the following security and non-security issues:

- bnc#908128: Check for bad invalid name sizes (CVE-2014-8118)
- bnc#906803: Create files with mode 0 (CVE-2013-6435)
- bnc#892431: Honor --noglob in install mode
- bnc#911228: Fix noglob patch, it broke files with space." );
	script_tag( name: "affected", value: "'rpm' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Software Development Kit 12." );
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
	if(!isnull( res = isrpmvuln( pkg: "rpm-32bit", rpm: "rpm-32bit~4.11.2~10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm", rpm: "rpm~4.11.2~10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-build", rpm: "rpm-build~4.11.2~10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-build-debuginfo", rpm: "rpm-build-debuginfo~4.11.2~10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-debuginfo-32bit", rpm: "rpm-debuginfo-32bit~4.11.2~10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-debuginfo", rpm: "rpm-debuginfo~4.11.2~10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-debugsource", rpm: "rpm-debugsource~4.11.2~10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-python", rpm: "rpm-python~4.11.2~10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-python-debuginfo", rpm: "rpm-python-debuginfo~4.11.2~10.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-python-debugsource", rpm: "rpm-python-debugsource~4.11.2~10.1", rls: "SLES12.0" ) )){
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

