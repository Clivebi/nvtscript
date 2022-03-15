if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.869534" );
	script_version( "2020-01-24T07:57:30+0000" );
	script_tag( name: "last_modification", value: "2020-01-24 07:57:30 +0000 (Fri, 24 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-07-07 06:22:59 +0200 (Tue, 07 Jul 2015)" );
	script_cve_id( "CVE-2015-3315", "CVE-2015-3142", "CVE-2015-1869", "CVE-2015-1870", "CVE-2015-3151", "CVE-2015-3150", "CVE-2015-3159" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for gnome-abrt FEDORA-2015-9886" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnome-abrt'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "gnome-abrt on Fedora 22" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2015-9886" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2015-June/160568.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC22" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC22"){
	if(( res = isrpmvuln( pkg: "gnome-abrt", rpm: "gnome-abrt~1.2.0~1.fc22", rls: "FC22" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

