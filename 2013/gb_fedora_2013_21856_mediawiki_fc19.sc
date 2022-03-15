if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.867095" );
	script_version( "2020-02-13T09:17:49+0000" );
	script_tag( name: "last_modification", value: "2020-02-13 09:17:49 +0000 (Thu, 13 Feb 2020)" );
	script_tag( name: "creation_date", value: "2013-12-03 14:41:45 +0530 (Tue, 03 Dec 2013)" );
	script_cve_id( "CVE-2013-4567", "CVE-2013-4568", "CVE-2013-4572", "CVE-2013-4569", "CVE-2013-4573", "CVE-2012-5394" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Fedora Update for mediawiki FEDORA-2013-21856" );
	script_tag( name: "affected", value: "mediawiki on Fedora 19" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "FEDORA", value: "2013-21856" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123011.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mediawiki'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC19" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC19"){
	if(( res = isrpmvuln( pkg: "mediawiki", rpm: "mediawiki~1.21.3~1.fc19", rls: "FC19" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

