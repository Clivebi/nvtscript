if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.123989" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-10-06 14:11:16 +0300 (Tue, 06 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Oracle Linux Local Check: ELSA-2012-0137" );
	script_tag( name: "insight", value: "ELSA-2012-0137 - texlive security update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2012-0137" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2012-0137.html" );
	script_cve_id( "CVE-2010-2642", "CVE-2011-0433", "CVE-2011-0764", "CVE-2011-1552", "CVE-2011-1553", "CVE-2011-1554" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/oracle_linux", "ssh/login/release",  "ssh/login/release=OracleLinux6" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
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
if(release == "OracleLinux6"){
	if(( res = isrpmvuln( pkg: "kpathsea", rpm: "kpathsea~2007~57.el6_2", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kpathsea-devel", rpm: "kpathsea-devel~2007~57.el6_2", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mendexk", rpm: "mendexk~2.6e~57.el6_2", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "texlive", rpm: "texlive~2007~57.el6_2", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "texlive-afm", rpm: "texlive-afm~2007~57.el6_2", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "texlive-context", rpm: "texlive-context~2007~57.el6_2", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "texlive-dvips", rpm: "texlive-dvips~2007~57.el6_2", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "texlive-dviutils", rpm: "texlive-dviutils~2007~57.el6_2", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "texlive-east-asian", rpm: "texlive-east-asian~2007~57.el6_2", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "texlive-latex", rpm: "texlive-latex~2007~57.el6_2", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "texlive-utils", rpm: "texlive-utils~2007~57.el6_2", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "texlive-xetex", rpm: "texlive-xetex~2007~57.el6_2", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );

