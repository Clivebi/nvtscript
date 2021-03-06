if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.867844" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-06-02 12:50:50 +0530 (Mon, 02 Jun 2014)" );
	script_cve_id( "CVE-2014-0213", "CVE-2014-0214", "CVE-2014-0215", "CVE-2014-0216", "CVE-2014-0217", "CVE-2014-0218", "CVE-2014-0122", "CVE-2014-0123", "CVE-2014-0124", "CVE-2014-0125", "CVE-2014-0126", "CVE-2014-0127", "CVE-2014-0129", "CVE-2014-0008", "CVE-2012-6087" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Fedora Update for moodle FEDORA-2014-6577" );
	script_tag( name: "affected", value: "moodle on Fedora 19" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "FEDORA", value: "2014-6577" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2014-May/133813.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'moodle'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "moodle", rpm: "moodle~2.4.10~1.fc19", rls: "FC19" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

