if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.1705.1" );
	script_cve_id( "CVE-2017-9148" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:1705-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:1705-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20171705-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'freeradius-server' package(s) announced via the SUSE-SU-2017:1705-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for freeradius-server fixes the following issues:
Security issue fixed:
- CVE-2017-9148: Disable OpenSSL's internal session cache to mitigate
 authentication bypass. (bsc#1041445)
Non security issue fixed:
- Fix case insensitive matching in compiled regular expressions
 (bsc#1027243)" );
	script_tag( name: "affected", value: "'freeradius-server' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP2." );
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server", rpm: "freeradius-server~3.0.3~17.4.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-debuginfo", rpm: "freeradius-server-debuginfo~3.0.3~17.4.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-debugsource", rpm: "freeradius-server-debugsource~3.0.3~17.4.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-doc", rpm: "freeradius-server-doc~3.0.3~17.4.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-krb5", rpm: "freeradius-server-krb5~3.0.3~17.4.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-krb5-debuginfo", rpm: "freeradius-server-krb5-debuginfo~3.0.3~17.4.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-ldap", rpm: "freeradius-server-ldap~3.0.3~17.4.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-ldap-debuginfo", rpm: "freeradius-server-ldap-debuginfo~3.0.3~17.4.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-libs", rpm: "freeradius-server-libs~3.0.3~17.4.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-libs-debuginfo", rpm: "freeradius-server-libs-debuginfo~3.0.3~17.4.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-mysql", rpm: "freeradius-server-mysql~3.0.3~17.4.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-mysql-debuginfo", rpm: "freeradius-server-mysql-debuginfo~3.0.3~17.4.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-perl", rpm: "freeradius-server-perl~3.0.3~17.4.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-perl-debuginfo", rpm: "freeradius-server-perl-debuginfo~3.0.3~17.4.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-postgresql", rpm: "freeradius-server-postgresql~3.0.3~17.4.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-postgresql-debuginfo", rpm: "freeradius-server-postgresql-debuginfo~3.0.3~17.4.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-python", rpm: "freeradius-server-python~3.0.3~17.4.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-python-debuginfo", rpm: "freeradius-server-python-debuginfo~3.0.3~17.4.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-sqlite", rpm: "freeradius-server-sqlite~3.0.3~17.4.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-sqlite-debuginfo", rpm: "freeradius-server-sqlite-debuginfo~3.0.3~17.4.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-utils", rpm: "freeradius-server-utils~3.0.3~17.4.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freeradius-server-utils-debuginfo", rpm: "freeradius-server-utils-debuginfo~3.0.3~17.4.1", rls: "SLES12.0SP2" ) )){
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

