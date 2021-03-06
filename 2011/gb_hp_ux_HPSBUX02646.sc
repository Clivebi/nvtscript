if(description){
	script_xref( name: "URL", value: "http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c02753287" );
	script_oid( "1.3.6.1.4.1.25623.1.0.835254" );
	script_version( "$Revision: 11739 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-04 09:49:31 +0200 (Thu, 04 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-06-06 16:56:27 +0200 (Mon, 06 Jun 2011)" );
	script_xref( name: "HPSBUX", value: "02646" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:S/C:N/I:N/A:C" );
	script_cve_id( "CVE-2011-0891" );
	script_name( "HP-UX Update for HP-UX Pkg HPSBUX02646" );
	script_tag( name: "summary", value: "The remote host is missing an update for the HP-UX Pkg package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "HP-UX Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/hp_hp-ux", "ssh/login/hp_pkgrev",  "ssh/login/release=HPUX(11\\.31|11\\.23)" );
	script_tag( name: "impact", value: "Local Denial of Service (DoS)" );
	script_tag( name: "affected", value: "HP-UX Pkg on HP-UX B.11.23 and B.11.31" );
	script_tag( name: "insight", value: "A potential security vulnerability have been identified with HP-UX. The
  vulnerability could be exploited locally to create a Denial of Service
  (DoS)." );
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
	if(( res = ishpuxpkgvuln( pkg: "OS-Core.CORE2-KRN", patch_list: ["PHKL_41945"], rls: "HPUX11.31" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "HPUX11.23"){
	if(( res = ishpuxpkgvuln( pkg: "ProgSupport.C2-INC", patch_list: ["PHKL_41944"], rls: "HPUX11.23" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = ishpuxpkgvuln( pkg: "OS-Core.CORE2-KRN", patch_list: ["PHKL_41944"], rls: "HPUX11.23" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

