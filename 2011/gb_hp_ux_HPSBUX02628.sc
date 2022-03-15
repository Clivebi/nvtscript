if(description){
	script_xref( name: "URL", value: "http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c02702395" );
	script_oid( "1.3.6.1.4.1.25623.1.0.835249" );
	script_version( "$Revision: 11739 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-04 09:49:31 +0200 (Thu, 04 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-02-28 16:24:14 +0100 (Mon, 28 Feb 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "HPSBUX", value: "02628" );
	script_cve_id( "CVE-2010-4435" );
	script_name( "HP-UX Update for CDE Calendar Manager HPSBUX02628" );
	script_tag( name: "summary", value: "The remote host is missing an update for the CDE Calendar Manager package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "HP-UX Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/hp_hp-ux", "ssh/login/hp_pkgrev",  "ssh/login/release=HPUX(11\\.31|11\\.23)" );
	script_tag( name: "impact", value: "Remote execution of arbitrary code" );
	script_tag( name: "affected", value: "CDE Calendar Manager on HP-UX B.11.23 and HP-UX B.11.31 running" );
	script_tag( name: "insight", value: "A potential security vulnerability has been identified with HP-UX running
  CDE Calendar Manager. The vulnerability could be exploited remotely to
  execute arbitrary code." );
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
	if(( res = ishpuxpkgvuln( pkg: "CDE.CDE-RUN", patch_list: ["PHSS_41788"], rls: "HPUX11.31" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "HPUX11.23"){
	if(( res = ishpuxpkgvuln( pkg: "CDE.CDE-RUN", patch_list: ["PHSS_41174"], rls: "HPUX11.23" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

