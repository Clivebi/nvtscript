if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.2502.1" );
	script_cve_id( "CVE-2018-5740", "CVE-2018-5743", "CVE-2018-5745", "CVE-2019-6465", "CVE-2019-6471" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:2502-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:2502-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20192502-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bind' package(s) announced via the SUSE-SU-2019:2502-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for bind fixes the following issues:

Security issues fixed:
CVE-2019-6465: Fixed an issue where controls for zone transfers may not
 be properly applied to Dynamically Loadable Zones (bsc#1126069).

CVE-2019-6471: Fixed a reachable assert in dispatch.c. (bsc#1138687)

CVE-2018-5745: Fixed a denial of service vulnerability if a trust anchor
 rolls over to an unsupported key algorithm when using managed-keys
 (bsc#1126068).

CVE-2018-5743: Fixed a denial of service vulnerability which could be
 caused by to many simultaneous TCP connections (bsc#1133185).

CVE-2018-5740: Fixed a denial of service vulnerability in the
 'deny-answer-aliases' feature (bsc#1104129).

Non-security issues fixed:
Don't rely on /etc/insserv.conf anymore for proper dependencies against
 nss-lookup.target in named.service and lwresd.service (bsc#1118367,
 bsc#1118368).

Fix FIPS related regression (bsc#1128220)." );
	script_tag( name: "affected", value: "'bind' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP4." );
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "bind", rpm: "bind~9.11.2~3.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-chrootenv", rpm: "bind-chrootenv~9.11.2~3.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-debuginfo", rpm: "bind-debuginfo~9.11.2~3.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-debugsource", rpm: "bind-debugsource~9.11.2~3.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-doc", rpm: "bind-doc~9.11.2~3.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-utils", rpm: "bind-utils~9.11.2~3.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bind-utils-debuginfo", rpm: "bind-utils-debuginfo~9.11.2~3.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbind9-160", rpm: "libbind9-160~9.11.2~3.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbind9-160-debuginfo", rpm: "libbind9-160-debuginfo~9.11.2~3.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdns169", rpm: "libdns169~9.11.2~3.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdns169-debuginfo", rpm: "libdns169-debuginfo~9.11.2~3.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libirs160", rpm: "libirs160~9.11.2~3.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libirs160-debuginfo", rpm: "libirs160-debuginfo~9.11.2~3.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisc166-32bit", rpm: "libisc166-32bit~9.11.2~3.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisc166", rpm: "libisc166~9.11.2~3.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisc166-debuginfo-32bit", rpm: "libisc166-debuginfo-32bit~9.11.2~3.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisc166-debuginfo", rpm: "libisc166-debuginfo~9.11.2~3.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisccc160", rpm: "libisccc160~9.11.2~3.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisccc160-debuginfo", rpm: "libisccc160-debuginfo~9.11.2~3.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisccfg160", rpm: "libisccfg160~9.11.2~3.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libisccfg160-debuginfo", rpm: "libisccfg160-debuginfo~9.11.2~3.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liblwres160", rpm: "liblwres160~9.11.2~3.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "liblwres160-debuginfo", rpm: "liblwres160-debuginfo~9.11.2~3.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-bind", rpm: "python-bind~9.11.2~3.10.1", rls: "SLES12.0SP4" ) )){
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

