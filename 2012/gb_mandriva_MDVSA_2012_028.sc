if(description){
	script_xref( name: "URL", value: "http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:028" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831558" );
	script_version( "2020-04-21T06:28:23+0000" );
	script_tag( name: "last_modification", value: "2020-04-21 06:28:23 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-03-07 11:20:44 +0530 (Wed, 07 Mar 2012)" );
	script_cve_id( "CVE-2011-3970" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_xref( name: "MDVSA", value: "2012:028" );
	script_name( "Mandriva Update for libxslt MDVSA-2012:028 (libxslt)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libxslt'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_(2011\\.0|mes5\\.2|2010\\.1)" );
	script_tag( name: "affected", value: "libxslt on Mandriva Linux 2011.0,
  Mandriva Enterprise Server 5.2,
  Mandriva Linux 2010.1" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "A vulnerability has been found and corrected in libxslt:

  libxslt allows remote attackers to cause a denial of service
  (out-of-bounds read) via unspecified vectors (CVE-2011-3970).

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
	if(( res = isrpmvuln( pkg: "libxslt1", rpm: "libxslt1~1.1.26~4.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxslt-devel", rpm: "libxslt-devel~1.1.26~4.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-libxslt", rpm: "python-libxslt~1.1.26~4.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xsltproc", rpm: "xsltproc~1.1.26~4.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64xslt1", rpm: "lib64xslt1~1.1.26~4.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64xslt-devel", rpm: "lib64xslt-devel~1.1.26~4.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_mes5.2"){
	if(( res = isrpmvuln( pkg: "libxslt1", rpm: "libxslt1~1.1.24~3.1mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxslt-devel", rpm: "libxslt-devel~1.1.24~3.1mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxslt-proc", rpm: "libxslt-proc~1.1.24~3.1mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-libxslt", rpm: "python-libxslt~1.1.24~3.1mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64xslt1", rpm: "lib64xslt1~1.1.24~3.1mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64xslt-devel", rpm: "lib64xslt-devel~1.1.24~3.1mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2010.1"){
	if(( res = isrpmvuln( pkg: "libxslt1", rpm: "libxslt1~1.1.26~2.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxslt-devel", rpm: "libxslt-devel~1.1.26~2.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-libxslt", rpm: "python-libxslt~1.1.26~2.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xsltproc", rpm: "xsltproc~1.1.26~2.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64xslt1", rpm: "lib64xslt1~1.1.26~2.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64xslt-devel", rpm: "lib64xslt-devel~1.1.26~2.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

