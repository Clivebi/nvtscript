if(description){
	script_xref( name: "URL", value: "http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c02783438" );
	script_oid( "1.3.6.1.4.1.25623.1.0.835255" );
	script_version( "$Revision: 11739 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-04 09:49:31 +0200 (Thu, 04 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-05-05 07:14:22 +0200 (Thu, 05 May 2011)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_xref( name: "HPSBUX", value: "02655" );
	script_cve_id( "CVE-2010-3613" );
	script_name( "HP-UX Update for BIND HPSBUX02655" );
	script_tag( name: "summary", value: "The remote host is missing an update for the BIND package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "HP-UX Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/hp_hp-ux", "ssh/login/hp_pkgrev",  "ssh/login/release=HPUX(11\\.31|11\\.23|11\\.11)" );
	script_tag( name: "impact", value: "Remote" );
	script_tag( name: "affected", value: "BIND on HP-UX B.11.31 running BIND 9.3 prior to C.9.3.2.9.0 HP-UX B.11.11 and
  B.11.23 running BIND 9.3 prior to C.9.3.2.8.0" );
	script_tag( name: "insight", value: "A potential security vulnerability has been identified with HP-UX running
  BIND. This vulnerability could beexploited remotely to create a Denial of
  Service (DoS)." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-hpux.inc.sc");
release = hpux_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "HPUX11.31"){
	if(( res = ishpuxpkgvuln( pkg: "NameService.BIND-AUX", revision: "C.9.3.2.9.0", rls: "HPUX11.31" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = ishpuxpkgvuln( pkg: "NameService.BIND-RUN", revision: "C.9.3.2.9.0", rls: "HPUX11.31" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "HPUX11.23"){
	if(( res = ishpuxpkgvuln( pkg: "BindUpgrade.BIND-UPGRADE", revision: "C.9.3.2.8.0", rls: "HPUX11.23" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = ishpuxpkgvuln( pkg: "BindUpgrade.BIND2-UPGRADE", revision: "C.9.3.2.8.0", rls: "HPUX11.23" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "HPUX11.11"){
	if(( res = ishpuxpkgvuln( pkg: "BindUpgrade.BIND-UPGRADE", revision: "C.9.3.2.8.0", rls: "HPUX11.11" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

