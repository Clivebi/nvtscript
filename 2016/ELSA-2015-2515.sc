if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.122873" );
	script_version( "2021-09-20T12:38:59+0000" );
	script_tag( name: "creation_date", value: "2016-02-05 14:01:41 +0200 (Fri, 05 Feb 2016)" );
	script_tag( name: "last_modification", value: "2021-09-20 12:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_name( "Oracle Linux Local Check: ELSA-2015-2515" );
	script_tag( name: "insight", value: "ELSA-2015-2515 - git19-git security update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2015-2515" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2015-2515.html" );
	script_cve_id( "CVE-2015-7545" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/oracle_linux", "ssh/login/release",  "ssh/login/release=OracleLinux(7|6)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Eero Volotinen" );
	script_family( "Oracle Linux Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "OracleLinux7"){
	if(( res = isrpmvuln( pkg: "git19-emacs-git", rpm: "git19-emacs-git~1.9.4~3.el7.1", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-emacs-git-el", rpm: "git19-emacs-git-el~1.9.4~3.el7.1", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-git", rpm: "git19-git~1.9.4~3.el7.1", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-git-all", rpm: "git19-git-all~1.9.4~3.el7.1", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-git-bzr", rpm: "git19-git-bzr~1.9.4~3.el7.1", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-git-cvs", rpm: "git19-git-cvs~1.9.4~3.el7.1", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-git-daemon", rpm: "git19-git-daemon~1.9.4~3.el7.1", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-git-email", rpm: "git19-git-email~1.9.4~3.el7.1", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-git-gui", rpm: "git19-git-gui~1.9.4~3.el7.1", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-git-hg", rpm: "git19-git-hg~1.9.4~3.el7.1", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-git-svn", rpm: "git19-git-svn~1.9.4~3.el7.1", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-gitk", rpm: "git19-gitk~1.9.4~3.el7.1", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-gitweb", rpm: "git19-gitweb~1.9.4~3.el7.1", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-perl-Git", rpm: "git19-perl-Git~1.9.4~3.el7.1", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-perl-Git-SVN", rpm: "git19-perl-Git-SVN~1.9.4~3.el7.1", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(release == "OracleLinux6"){
	if(( res = isrpmvuln( pkg: "git19-emacs-git", rpm: "git19-emacs-git~1.9.4~3.el6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-emacs-git-el", rpm: "git19-emacs-git-el~1.9.4~3.el6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-git", rpm: "git19-git~1.9.4~3.el6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-git-all", rpm: "git19-git-all~1.9.4~3.el6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-git-cvs", rpm: "git19-git-cvs~1.9.4~3.el6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-git-daemon", rpm: "git19-git-daemon~1.9.4~3.el6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-git-email", rpm: "git19-git-email~1.9.4~3.el6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-git-gui", rpm: "git19-git-gui~1.9.4~3.el6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-git-svn", rpm: "git19-git-svn~1.9.4~3.el6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-gitk", rpm: "git19-gitk~1.9.4~3.el6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-gitweb", rpm: "git19-gitweb~1.9.4~3.el6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-perl-Git", rpm: "git19-perl-Git~1.9.4~3.el6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git19-perl-Git-SVN", rpm: "git19-perl-Git-SVN~1.9.4~3.el6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );

