if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.868181" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-09-11 05:56:54 +0200 (Thu, 11 Sep 2014)" );
	script_cve_id( "CVE-2014-2440", "CVE-2014-0384", "CVE-2014-2432", "CVE-2014-2431", "CVE-2014-2430", "CVE-2014-2436", "CVE-2014-2438", "CVE-2014-2419", "CVE-2014-0001", "CVE-2014-0412", "CVE-2014-0437", "CVE-2013-5908", "CVE-2014-0420", "CVE-2014-0393", "CVE-2013-5891", "CVE-2014-0386", "CVE-2014-0401", "CVE-2014-0402" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Fedora Update for mariadb FEDORA-2014-9956" );
	script_tag( name: "affected", value: "mariadb on Fedora 20" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "FEDORA", value: "2014-9956" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2014-September/137559.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mariadb'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "mariadb", rpm: "mariadb~5.5.39~1.fc20", rls: "FC20" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

