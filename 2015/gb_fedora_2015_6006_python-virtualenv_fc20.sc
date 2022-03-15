if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.869280" );
	script_version( "2019-11-15T08:07:38+0000" );
	script_tag( name: "last_modification", value: "2019-11-15 08:07:38 +0000 (Fri, 15 Nov 2019)" );
	script_tag( name: "creation_date", value: "2015-04-22 07:21:23 +0200 (Wed, 22 Apr 2015)" );
	script_cve_id( "CVE-2013-5123" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for python-virtualenv FEDORA-2015-6006" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-virtualenv'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "python-virtualenv on Fedora 20" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2015-6006" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2015-April/155291.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC20" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC20"){
	if(( res = isrpmvuln( pkg: "python-virtualenv", rpm: "python-virtualenv~12.0.7~1.fc20", rls: "FC20" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

