if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.866948" );
	script_version( "2021-07-05T02:00:48+0000" );
	script_tag( name: "last_modification", value: "2021-07-05 02:00:48 +0000 (Mon, 05 Jul 2021)" );
	script_tag( name: "creation_date", value: "2013-10-03 10:15:01 +0530 (Thu, 03 Oct 2013)" );
	script_cve_id( "CVE-2012-2142" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-15 18:30:00 +0000 (Wed, 15 Jan 2020)" );
	script_name( "Fedora Update for xpdf FEDORA-2013-17375" );
	script_tag( name: "affected", value: "xpdf on Fedora 18" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "FEDORA", value: "2013-17375" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-October/117721.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xpdf'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC18" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC18"){
	if(( res = isrpmvuln( pkg: "xpdf", rpm: "xpdf~3.03~8.fc18", rls: "FC18" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
