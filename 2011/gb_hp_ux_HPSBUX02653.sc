if(description){
	script_xref( name: "URL", value: "http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c02777287" );
	script_oid( "1.3.6.1.4.1.25623.1.0.835256" );
	script_version( "$Revision: 11739 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-04 09:49:31 +0200 (Thu, 04 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-05-05 07:14:22 +0200 (Thu, 05 May 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_xref( name: "HPSBUX", value: "02653" );
	script_cve_id( "CVE-2011-0896" );
	script_name( "HP-UX Update for NFS/ONCplus HPSBUX02653" );
	script_tag( name: "summary", value: "The remote host is missing an update for the NFS/ONCplus package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "HP-UX Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/hp_hp-ux", "ssh/login/hp_pkgrev",  "ssh/login/release=HPUX11\\.31" );
	script_tag( name: "impact", value: "Remote Denial of Service (DoS)" );
	script_tag( name: "affected", value: "NFS/ONCplus on HP-UX B.11.31 running NFS / ONCplus version B.11.31.10 or previous" );
	script_tag( name: "insight", value: "A potential security vulnerability has been identified with NFS/ONCplus
  running on HP-UX. The vulnerability could result in a remote Denial of
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
	if(( res = ishpuxpkgvuln( pkg: "NFS.KEY-CORE", revision: "B.11.31.11", rls: "HPUX11.31" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = ishpuxpkgvuln( pkg: "NFS.NFS-64ALIB", revision: "B.11.31.11", rls: "HPUX11.31" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = ishpuxpkgvuln( pkg: "NFS.NFS-64SLIB", revision: "B.11.31.11", rls: "HPUX11.31" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = ishpuxpkgvuln( pkg: "NFS.NFS-CLIENT", revision: "B.11.31.11", rls: "HPUX11.31" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = ishpuxpkgvuln( pkg: "NFS.NFS-CORE", revision: "B.11.31.11", rls: "HPUX11.31" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = ishpuxpkgvuln( pkg: "NFS.NFS-KRN", revision: "B.11.31.11", rls: "HPUX11.31" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = ishpuxpkgvuln( pkg: "NFS.NFS-PRG", revision: "B.11.31.11", rls: "HPUX11.31" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = ishpuxpkgvuln( pkg: "NFS.NFS-SERVER", revision: "B.11.31.11", rls: "HPUX11.31" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = ishpuxpkgvuln( pkg: "NFS.NFS-SHLIBS", revision: "B.11.31.11", rls: "HPUX11.31" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = ishpuxpkgvuln( pkg: "NFS.NFS2-CLIENT", revision: "B.11.31.11", rls: "HPUX11.31" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = ishpuxpkgvuln( pkg: "NFS.NFS2-CORE", revision: "B.11.31.11", rls: "HPUX11.31" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = ishpuxpkgvuln( pkg: "NFS.NFS2-PRG", revision: "B.11.31.11", rls: "HPUX11.31" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = ishpuxpkgvuln( pkg: "NFS.NFS2-SERVER", revision: "B.11.31.11", rls: "HPUX11.31" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = ishpuxpkgvuln( pkg: "NFS.NIS-CLIENT", revision: "B.11.31.11", rls: "HPUX11.31" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = ishpuxpkgvuln( pkg: "NFS.NIS-CORE", revision: "B.11.31.11", rls: "HPUX11.31" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = ishpuxpkgvuln( pkg: "NFS.NIS-SERVER", revision: "B.11.31.11", rls: "HPUX11.31" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = ishpuxpkgvuln( pkg: "NFS.NIS2-CLIENT", revision: "B.11.31.11", rls: "HPUX11.31" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = ishpuxpkgvuln( pkg: "NFS.NIS2-CORE", revision: "B.11.31.11", rls: "HPUX11.31" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = ishpuxpkgvuln( pkg: "NFS.NIS2-SERVER", revision: "B.11.31.11", rls: "HPUX11.31" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

