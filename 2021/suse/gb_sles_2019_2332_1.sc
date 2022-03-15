if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.2332.1" );
	script_cve_id( "CVE-2019-11236", "CVE-2019-11324", "CVE-2019-9740" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:19 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-15 21:15:00 +0000 (Tue, 15 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:2332-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:2332-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20192332-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-urllib3' package(s) announced via the SUSE-SU-2019:2332-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python-urllib3 fixes the following issues:

Security issues fixed:
CVE-2019-9740: Fixed CRLF injection issue (bsc#1129071).

CVE-2019-11324: Fixed invalid CA certificat verification (bsc#1132900).

CVE-2019-11236: Fixed CRLF injection via request parameter (bsc#1132663)." );
	script_tag( name: "affected", value: "'python-urllib3' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Python2 15-SP1." );
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
if(release == "SLES15.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "python3-urllib3", rpm: "python3-urllib3~1.24~9.4.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-urllib3", rpm: "python2-urllib3~1.24~9.4.1", rls: "SLES15.0SP1" ) )){
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

