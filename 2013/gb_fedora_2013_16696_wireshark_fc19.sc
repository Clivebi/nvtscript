if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.866892" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-09-18 10:07:23 +0530 (Wed, 18 Sep 2013)" );
	script_cve_id( "CVE-2013-4920", "CVE-2013-4921", "CVE-2013-4922", "CVE-2013-4923", "CVE-2013-4924", "CVE-2013-4925", "CVE-2013-4926", "CVE-2013-4927" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "Fedora Update for wireshark FEDORA-2013-16696" );
	script_tag( name: "affected", value: "wireshark on Fedora 19" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "FEDORA", value: "2013-16696" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-September/115744.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wireshark'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "wireshark", rpm: "wireshark~1.10.2~5.fc19", rls: "FC19" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

