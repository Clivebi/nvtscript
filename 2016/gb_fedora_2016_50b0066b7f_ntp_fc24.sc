if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808467" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-06-19 05:26:03 +0200 (Sun, 19 Jun 2016)" );
	script_cve_id( "CVE-2015-8139", "CVE-2016-4954", "CVE-2016-4955", "CVE-2016-4956", "CVE-2016-1548" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for ntp FEDORA-2016-50b0066b7f" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ntp'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "ntp on Fedora 24" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2016-50b0066b7f" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/K3EYJQHJZ2KTVQ7ICEFHXTLZ36MRASWX" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC24" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC24"){
	if(( res = isrpmvuln( pkg: "ntp", rpm: "ntp~4.2.6p5~41.fc24", rls: "FC24" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

