if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871566" );
	script_version( "2021-09-20T10:01:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 10:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-03-03 06:26:38 +0100 (Thu, 03 Mar 2016)" );
	script_cve_id( "CVE-2016-0773" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-09 02:29:00 +0000 (Sat, 09 Dec 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for postgresql RHSA-2016:0347-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "PostgreSQL is an advanced object-relational
  database management system (DBMS).

  An integer overflow flaw, leading to a heap-based buffer overflow, was
  found in the PostgreSQL handling code for regular expressions. A remote
  attacker could use a specially crafted regular expression to cause
  PostgreSQL to crash or possibly execute arbitrary code. (CVE-2016-0773)

  Red Hat would like to thank PostgreSQL upstream for reporting this issue.
  Upstream acknowledges Tom Lane and Greg Stark as the original reporters.

  All PostgreSQL users are advised to upgrade to these updated packages,
  which contain a backported patch to correct this issue. If the postgresql
  service is running, it will be automatically restarted after installing
  this update." );
	script_tag( name: "affected", value: "postgresql on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2016:0347-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2016-March/msg00010.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_6"){
	if(( res = isrpmvuln( pkg: "postgresql", rpm: "postgresql~8.4.20~5.el6_7", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-contrib", rpm: "postgresql-contrib~8.4.20~5.el6_7", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-debuginfo", rpm: "postgresql-debuginfo~8.4.20~5.el6_7", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-devel", rpm: "postgresql-devel~8.4.20~5.el6_7", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-docs", rpm: "postgresql-docs~8.4.20~5.el6_7", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-libs", rpm: "postgresql-libs~8.4.20~5.el6_7", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-plperl", rpm: "postgresql-plperl~8.4.20~5.el6_7", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-plpython", rpm: "postgresql-plpython~8.4.20~5.el6_7", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-pltcl", rpm: "postgresql-pltcl~8.4.20~5.el6_7", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-server", rpm: "postgresql-server~8.4.20~5.el6_7", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postgresql-test", rpm: "postgresql-test~8.4.20~5.el6_7", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

