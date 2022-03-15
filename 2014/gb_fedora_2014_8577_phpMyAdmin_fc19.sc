if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.868056" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-08-05 16:46:18 +0530 (Tue, 05 Aug 2014)" );
	script_cve_id( "CVE-2013-4998", "CVE-2013-4999", "CVE-2013-5000", "CVE-2013-5003", "CVE-2013-5029", "CVE-2014-1879", "CVE-2014-4348", "CVE-2014-4349" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_name( "Fedora Update for phpMyAdmin FEDORA-2014-8577" );
	script_tag( name: "affected", value: "phpMyAdmin on Fedora 19" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "FEDORA", value: "2014-8577" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2014-July/136156.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'phpMyAdmin'
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
	if(( res = isrpmvuln( pkg: "phpMyAdmin", rpm: "phpMyAdmin~4.2.6~1.fc19", rls: "FC19" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

