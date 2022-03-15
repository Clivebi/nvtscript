if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876503" );
	script_version( "2021-08-31T14:01:23+0000" );
	script_cve_id( "CVE-2019-9946" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-31 14:01:23 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-06-15 02:10:02 +0000 (Sat, 15 Jun 2019)" );
	script_name( "Fedora Update for containernetworking-plugins FEDORA-2019-24217abfdf" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-24217abfdf" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SGOOWAELGH3F7OXRBPH3HCNZELNLXYTW" );
	script_tag( name: "summary", value: "The remote host is missing an update for the
  'containernetworking-plugins' package(s) announced via the FEDORA-2019-24217abfdf
  advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "The CNI (Container Network Interface) project
  consists of a specification and libraries for writing plugins to configure
  network interfaces in Linux containers, along with a number of supported plugins.
  CNI concerns itself only with network connectivity of containers and removing
  allocated resources when the container is deleted." );
	script_tag( name: "affected", value: "'containernetworking-plugins' package(s) on Fedora 29." );
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
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "containernetworking-plugins", rpm: "containernetworking-plugins~0.7.5~1.fc29", rls: "FC29" ) )){
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

