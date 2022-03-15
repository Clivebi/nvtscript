if(description){
	script_xref( name: "URL", value: "http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:178" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831755" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-12-10 09:50:18 +0530 (Mon, 10 Dec 2012)" );
	script_cve_id( "CVE-2012-5611" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_xref( name: "MDVSA", value: "2012:178" );
	script_name( "Mandriva Update for mysql MDVSA-2012:178 (mysql)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mysql'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_2011\\.0" );
	script_tag( name: "affected", value: "mysql on Mandriva Linux 2011.0" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "A vulnerability was discovered and corrected in mysql:

  Stack-based buffer overflow in MySQL 5.5.19, 5.1.53, and possibly
  other versions, and MariaDB 5.5.2.x before 5.5.28a, 5.3.x before
  5.3.11, 5.2.x before 5.2.13 and 5.1.x before 5.1.66, allows remote
  authenticated users to execute arbitrary code via a long argument to
  the GRANT FILE command (CVE-2012-5611).

  The updated packages have been patched to correct this issue." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "MNDK_2011.0"){
	if(( res = isrpmvuln( pkg: "libmysql18", rpm: "libmysql18~5.5.28~0.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libmysqld0", rpm: "libmysqld0~5.5.28~0.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libmysql-devel", rpm: "libmysql-devel~5.5.28~0.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libmysqlservices0", rpm: "libmysqlservices0~5.5.28~0.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libmysql-static-devel", rpm: "libmysql-static-devel~5.5.28~0.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql", rpm: "mysql~5.5.28~0.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql-bench", rpm: "mysql-bench~5.5.28~0.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql-client", rpm: "mysql-client~5.5.28~0.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql-common", rpm: "mysql-common~5.5.28~0.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql-common-core", rpm: "mysql-common-core~5.5.28~0.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql-core", rpm: "mysql-core~5.5.28~0.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64mysql18", rpm: "lib64mysql18~5.5.28~0.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64mysqld0", rpm: "lib64mysqld0~5.5.28~0.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64mysql-devel", rpm: "lib64mysql-devel~5.5.28~0.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64mysqlservices0", rpm: "lib64mysqlservices0~5.5.28~0.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64mysql-static-devel", rpm: "lib64mysql-static-devel~5.5.28~0.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

