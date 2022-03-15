if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2012.0732.1" );
	script_cve_id( "CVE-2011-3048" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:27 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-29 02:29:00 +0000 (Fri, 29 Dec 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2012:0732-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP4|SLES11\\.0SP1|SLES11\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2012:0732-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2012/suse-su-20120732-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libpng' package(s) announced via the SUSE-SU-2012:0732-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The following security issue has been fixed:

 * specially crafted png files could have caused a memory corruption in libpng's png_set_text_2() function
(CVE-2011-3048).

Security Issue reference:

 * CVE-2011-3048
>" );
	script_tag( name: "affected", value: "'libpng' package(s) on SUSE Linux Enterprise Desktop 10 SP4, SUSE Linux Enterprise Desktop 11 SP1, SUSE Linux Enterprise Desktop 11 SP2, SUSE Linux Enterprise Server 10 SP4, SUSE Linux Enterprise Server 11 SP1, SUSE Linux Enterprise Server 11 SP2, SUSE Linux Enterprise Software Development Kit 11 SP1, SUSE Linux Enterprise Software Development Kit 11 SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "libpng", rpm: "libpng~1.2.8~19.35.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng-32bit", rpm: "libpng-32bit~1.2.8~19.35.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng-64bit", rpm: "libpng-64bit~1.2.8~19.35.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng-devel", rpm: "libpng-devel~1.2.8~19.35.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng-devel-32bit", rpm: "libpng-devel-32bit~1.2.8~19.35.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng-devel-64bit", rpm: "libpng-devel-64bit~1.2.8~19.35.4", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng-x86", rpm: "libpng-x86~1.2.8~19.35.4", rls: "SLES10.0SP4" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "libpng12-0", rpm: "libpng12-0~1.2.31~5.29.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng12-0-32bit", rpm: "libpng12-0-32bit~1.2.31~5.29.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng12-0-x86", rpm: "libpng12-0-x86~1.2.31~5.29.1", rls: "SLES11.0SP1" ) )){
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
if(release == "SLES11.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "libpng12-0", rpm: "libpng12-0~1.2.31~5.29.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng12-0-32bit", rpm: "libpng12-0-32bit~1.2.31~5.29.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng12-0-x86", rpm: "libpng12-0-x86~1.2.31~5.29.1", rls: "SLES11.0SP2" ) )){
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

