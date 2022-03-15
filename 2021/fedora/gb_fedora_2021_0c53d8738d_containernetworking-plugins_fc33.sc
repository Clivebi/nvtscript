if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879852" );
	script_version( "2021-08-03T06:52:21+0000" );
	script_cve_id( "CVE-2021-3602" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-03 06:52:21 +0000 (Tue, 03 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-27 03:23:12 +0000 (Tue, 27 Jul 2021)" );
	script_name( "Fedora: Security Advisory for containernetworking-plugins (FEDORA-2021-0c53d8738d)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-0c53d8738d" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZAB6D3CGIKTOPITATFKEJEJZRRFUNAAF" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'containernetworking-plugins'
  package(s) announced via the FEDORA-2021-0c53d8738d advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The CNI (Container Network Interface) project consists of a specification
and libraries for writing plugins to configure network interfaces in Linux
containers, along with a number of supported plugins. CNI concerns itself
only with network connectivity of containers and removing allocated resources
when the container is deleted." );
	script_tag( name: "affected", value: "'containernetworking-plugins' package(s) on Fedora 33." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "containernetworking-plugins", rpm: "containernetworking-plugins~1.0.0~0.2.rc1.fc33", rls: "FC33" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

